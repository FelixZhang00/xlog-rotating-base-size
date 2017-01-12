// Tencent is pleased to support the open source community by making Mars available.
// Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.

// Licensed under the MIT License (the "License"); you may not use this file except in 
// compliance with the License. You may obtain a copy of the License at
// http://opensource.org/licenses/MIT

// Unless required by applicable law or agreed to in writing, software distributed under the License is
// distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific language governing permissions and
// limitations under the License.


/*
 * appender.h
 *
 *  Created on: 2013-3-7
 *      Author: yerungui
 */

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "mars/log/appender.h"
#include <stdio.h>

#ifdef _WIN32
#define PRIdMAX "lld"
#define snprintf _snprintf
#define strcasecmp _stricmp
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define fileno _fileno
#else
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/mount.h>
#endif

#include <ctype.h>
#include <assert.h>

#include <unistd.h>
#include <zlib.h>

#include <string>
#include <algorithm>

#include "boost/bind.hpp"
#include "boost/iostreams/device/mapped_file.hpp"
#include "boost/filesystem.hpp"

#include "mars/comm/thread/lock.h"
#include "mars/comm/thread/condition.h"
#include "mars/comm/thread/thread.h"
#include "mars/comm/scope_recursion_limit.h"
#include "mars/comm/bootrun.h"
#include "mars/comm/tickcount.h"
#include "mars/comm/autobuffer.h"
#include "mars/comm/ptrbuffer.h"
#include "mars/comm/xlogger/xloggerbase.h"
#include "mars/comm/time_utils.h"
#include "mars/comm/strutil.h"
#include "mars/comm/mmap_util.h"
#include "mars/comm/tickcount.h"
#include "mars/comm/verinfo.h"

#include "log_buffer.h"

#include <sstream>

#define LOG_EXT "xlog"

extern void log_formater(const XLoggerInfo* _info, const char* _logbody, PtrBuffer& _log);
extern void ConsoleLog(const XLoggerInfo* _info, const char* _log);

static TAppenderMode sg_mode = kAppednerAsync;

static std::string sg_logdir;
static std::string sg_cache_logdir;
static std::string sg_logfileprefix;

static Mutex sg_mutex_log_file;
static FILE* sg_logfile = NULL;
static time_t sg_openfiletime = 0;
static std::string sg_current_dir;

static Mutex sg_mutex_buffer_async;
#ifdef _WIN32
static Condition& sg_cond_buffer_async = *(new Condition());  // 改成引用, 避免在全局释放时执行析构导致crash
#else
static Condition sg_cond_buffer_async;
#endif

static LogBuffer* sg_log_buff = NULL;

static volatile bool sg_log_close = true;

static Tss sg_tss_dumpfile(&free);

#ifdef DEBUG
static bool sg_consolelog_open = true;
#else
static bool sg_consolelog_open = false;
#endif

static void __async_log_thread();
static Thread sg_thread_async(&__async_log_thread);

static const unsigned int kBufferBlockLength = 150 * 1024;
static const long kMaxLogAliveTime = 10 * 24 * 60 * 60; // 10 days in second

static std::string sg_log_extra_msg;

static boost::iostreams::mapped_file sg_mmmap_file;


// 把原来xlog的dailylog策略替换成Rotating策略
static std::size_t sg_max_size = 1024*1024; //bytes
static std::size_t sg_max_files = 3;
static std::string sg_logfilename;
static bool __roate();
static std::string __calc_filename(const std::string& _logdir, const char* _prefix, const std::string& _fileext, unsigned int index);

///////////////////////////////////////

namespace {
class ScopeErrno {
  public:
    ScopeErrno() {m_errno = errno;}
    ~ScopeErrno() {errno = m_errno;}

  private:
    ScopeErrno(const ScopeErrno&);
    const ScopeErrno& operator=(const ScopeErrno&);

  private:
    int m_errno;
};

#define SCOPE_ERRNO() SCOPE_ERRNO_I(__LINE__)
#define SCOPE_ERRNO_I(line) SCOPE_ERRNO_II(line)
#define SCOPE_ERRNO_II(line) ScopeErrno __scope_errno_##line

}

static void __del_files(const std::string& _forder_path) {
    
    boost::filesystem::path path(_forder_path);
    if (!boost::filesystem::is_directory(path)) {
        return;
    }
    
    boost::filesystem::directory_iterator end_iter;
    for (boost::filesystem::directory_iterator iter(path); iter != end_iter; ++iter) {
        if (boost::filesystem::is_regular_file(iter->status()))
        {
            boost::filesystem::remove(iter->path());
        }
    }
}

static void __del_timeout_file(const std::string& _log_path) {
    time_t now_time = time(NULL);
    
    boost::filesystem::path path(_log_path);
    
    if (boost::filesystem::exists(path) && boost::filesystem::is_directory(path)){
        boost::filesystem::directory_iterator end_iter;
        for (boost::filesystem::directory_iterator iter(path); iter != end_iter; ++iter) {
            time_t fileModifyTime = boost::filesystem::last_write_time(iter->path());
            
            if (now_time > fileModifyTime && now_time - fileModifyTime > kMaxLogAliveTime) {
                if (boost::filesystem::is_regular_file(iter->status())) {
                    boost::filesystem::remove(iter->path());
                }
                else if (boost::filesystem::is_directory(iter->status())) {
                    __del_files(iter->path().string());
                }
            }
        }
    }
}

static bool __append_file(const std::string& _src_file, const std::string& _dst_file) {
    if (_src_file == _dst_file) {
        return false;
    }

    if (!boost::filesystem::exists(_src_file)){
        return false;
    }
    
    if (0 == boost::filesystem::file_size(_src_file)){
        return true;
    }

    FILE* src_file = fopen(_src_file.c_str(), "rb");

    if (NULL == src_file) {
        return false;
    }

    FILE* dest_file = fopen(_dst_file.c_str(), "ab");

    if (NULL == dest_file) {
        fclose(src_file);
        return false;
    }

    fseek(src_file, 0, SEEK_END);
    long src_file_len = ftell(src_file);
    long dst_file_len = ftell(dest_file);
    fseek(src_file, 0, SEEK_SET);

    char buffer[4096] = {0};

    while (true) {
        if (feof(src_file)) break;

        size_t read_ret = fread(buffer, 1, sizeof(buffer), src_file);

        if (read_ret == 0)   break;

        if (ferror(src_file)) break;

        fwrite(buffer, 1, read_ret, dest_file);

        if (ferror(dest_file))  break;
    }

    if (dst_file_len + src_file_len > ftell(dest_file)) {
        ftruncate(fileno(dest_file), dst_file_len);
        fclose(src_file);
        fclose(dest_file);
        return false;
    }

    fclose(src_file);
    fclose(dest_file);

    return true;
}

static void __move_old_files(const std::string& _src_path, const std::string& _dest_path, const std::string& _nameprefix) {
    if (_src_path == _dest_path) {
        return;
    }

    boost::filesystem::path path(_src_path);
    if (!boost::filesystem::is_directory(path)) {
        return;
    }
    
    ScopedLock lock_file(sg_mutex_log_file);
    
    boost::filesystem::directory_iterator end_iter;
    for (boost::filesystem::directory_iterator iter(path); iter != end_iter; ++iter) {
        
        if (!strutil::StartsWith(iter->path().string(), _nameprefix) || !strutil::EndsWith(iter->path().string(), LOG_EXT)) {
            continue;
        }
        
        std::string des_file_name = _dest_path + "/" + iter->path().filename().string();
        
        if (!__append_file(iter->path().string(), des_file_name)) {
            break;
        }
        
        boost::filesystem::remove(iter->path());
    }
}

static void __writetips2console(const char* _tips_format, ...) {
    
    if (NULL == _tips_format) {
        return;
    }
    
    XLoggerInfo info;
    memset(&info, 0, sizeof(XLoggerInfo));
    
    char tips_info[4096] = {0};
    va_list ap;
    va_start(ap, _tips_format);
    vsnprintf(tips_info, sizeof(tips_info), _tips_format, ap);
    va_end(ap);
    ConsoleLog(&info, tips_info);
}



////////////////////////////////////////////////
/**
* 
* 改写清理日志文件的策略为:rotating based on size
**/
static bool __writefile(const void* _data, size_t _len) {
    if (NULL == sg_logfile) {
        assert(false);
        return false;
    }

    long before_len = ftell(sg_logfile);
    if (before_len < 0) return false;

    // 如果发生了__roate，需要reopen sg_logfile
    if(before_len+_len > sg_max_size){
        if(!__roate()){
            return false;
        }
    }

    if (1 != fwrite(_data, _len, 1, sg_logfile)) {
        int err = ferror(sg_logfile);

        __writetips2console("write file error:%d", err);


        ftruncate(fileno(sg_logfile), before_len);
        fseek(sg_logfile, 0, SEEK_END);

        char err_log[256] = {0};
        snprintf(err_log, sizeof(err_log), "\nwrite file error:%d\n", err);

        char tmp[256] = {0};
        size_t len = sizeof(tmp);
        LogBuffer::Write(err_log, strnlen(err_log, sizeof(err_log)), tmp, len);

        fwrite(tmp, len, 1, sg_logfile);

        return false;
    }

    return true;
}

template <typename T>
std::string NumberToString ( T Number )
{
     std::ostringstream ss;
     ss << Number;
     return ss.str();
}

static std::string __calc_filename(const std::string& _logdir, const char* _prefix, const std::string& _fileext,unsigned int index){
    std::string logfilepath = _logdir;
    logfilepath += "/";
    logfilepath += _prefix;
    if(index){
        logfilepath += ".";
        logfilepath += NumberToString(index);
    }
    logfilepath += ".";
    logfilepath += _fileext;
    return logfilepath;
}


    // Rotate files:
    // log.txt -> log.1.txt
    // log.1.txt -> log2.txt
    // log.2.txt -> log3.txt
    // log.3.txt -> delete
static bool __roate(){
    if(sg_logfilename.empty() || sg_logdir.empty() || sg_logfileprefix.empty()){
        return false;
    }

    fclose(sg_logfile);
    sg_logfile = NULL;

    for(auto i = sg_max_files; i > 0; --i){
        std::string src = __calc_filename(sg_logdir,sg_logfileprefix.c_str(),LOG_EXT,i-1);
        std::string target = __calc_filename(sg_logdir,sg_logfileprefix.c_str(),LOG_EXT,i);
        boost::filesystem::path src_path(src);
        boost::filesystem::path target_path(target);

        if(boost::filesystem::exists(target_path)){
            boost::filesystem::remove(target_path);
        }
        if(boost::filesystem::exists(src_path)){
            boost::filesystem::rename(src_path,target_path);
        }

    }

    //reopen
    sg_logfile = fopen(sg_logfilename.c_str(), "wb");
    if (NULL == sg_logfile) {
        __writetips2console("open file error:%d %s, path:%s", errno, strerror(errno), sg_logfilename.c_str());
        return false;
    }

    return true;
}
 
static bool __openlogfile(const std::string& _log_dir){
    if (sg_logdir.empty()) return false;

    // 如果sg_logfile已经打开了，则直接返回。
    if (NULL != sg_logfile) {
        return true;
    }

    sg_current_dir = _log_dir;
    sg_logfilename = __calc_filename(_log_dir, sg_logfileprefix.c_str(), LOG_EXT,0);

    sg_logfile = fopen(sg_logfilename.c_str(), "ab");

    if (NULL == sg_logfile) {
        __writetips2console("open file error:%d %s, path:%s", errno, strerror(errno), sg_logfilename.c_str());
    }

    return NULL != sg_logfile;
}

////////////////////////////////////////////////


static void __closelogfile() {
    if (NULL == sg_logfile) return;

    sg_openfiletime = 0;
    fclose(sg_logfile);
    sg_logfile = NULL;
}

static void __log2file(const void* _data, size_t _len) {
    if (NULL == _data || 0 == _len || sg_logdir.empty()) {
        return;
    }

    ScopedLock lock_file(sg_mutex_log_file);

        if (__openlogfile(sg_logdir)) {
            __writefile(_data, _len);
            if (kAppednerAsync == sg_mode) {
                __closelogfile();
            }
        }
        return;

}


static void __writetips2file(const char* _tips_format, ...) {

    if (NULL == _tips_format) {
        return;
    }
    
    char tips_info[4096] = {0};
    va_list ap;
    va_start(ap, _tips_format);
    vsnprintf(tips_info, sizeof(tips_info), _tips_format, ap);
    va_end(ap);

    char tmp[8 * 1024] = {0};
    size_t len = sizeof(tmp);
    
    LogBuffer::Write(tips_info, strnlen(tips_info, sizeof(tips_info)), tmp, len);
    
    __log2file(tmp, len);
}

static void __async_log_thread() {
    while (true) {

        ScopedLock lock_buffer(sg_mutex_buffer_async);

        if (NULL == sg_log_buff) break;

        AutoBuffer tmp;
        sg_log_buff->Flush(tmp);
        lock_buffer.unlock();

        if (NULL != tmp.Ptr())  __log2file(tmp.Ptr(), tmp.Length());

        if (sg_log_close) break;

        sg_cond_buffer_async.wait(15 * 60 *1000);
    }
}

static void __appender_sync(const XLoggerInfo* _info, const char* _log) {

    char temp[16 * 1024] = {0};     // tell perry,ray if you want modify size.
    PtrBuffer log(temp, 0, sizeof(temp));
    log_formater(_info, _log, log);

    char buffer_crypt[16 * 1024] = {0};
    size_t len = 16 * 1024;
    if (!LogBuffer::Write(log.Ptr(), log.Length(), buffer_crypt, len))   return;

    __log2file(buffer_crypt, len);
}

static void __appender_async(const XLoggerInfo* _info, const char* _log) {
    ScopedLock lock(sg_mutex_buffer_async);
    if (NULL == sg_log_buff) return;

    char temp[16*1024] = {0};       //tell perry,ray if you want modify size.
    PtrBuffer log_buff(temp, 0, sizeof(temp));
    log_formater(_info, _log, log_buff);

    if (sg_log_buff->GetData().Length() >= kBufferBlockLength*4/5) {
       int ret = snprintf(temp, sizeof(temp), "[F][ sg_buffer_async.Length() >= BUFFER_BLOCK_LENTH*4/5, len: %d\n", (int)sg_log_buff->GetData().Length());
       log_buff.Length(ret, ret);
    }

    if (!sg_log_buff->Write(log_buff.Ptr(), (unsigned int)log_buff.Length())) return;

    if (sg_log_buff->GetData().Length() >= kBufferBlockLength*1/3 || (NULL!=_info && kLevelFatal == _info->level)) {
       sg_cond_buffer_async.notifyAll();
    }

}

////////////////////////////////////////////////////////////////////////////////////

void xlogger_appender(const XLoggerInfo* _info, const char* _log) {
    if (sg_log_close) return;

    SCOPE_ERRNO();

    DEFINE_SCOPERECURSIONLIMIT(recursion);
    static Tss s_recursion_str(free);

    if (sg_consolelog_open) ConsoleLog(_info,  _log);

    if (2 <= (int)recursion.Get() && NULL == s_recursion_str.get()) {
        if ((int)recursion.Get() > 10) return;
        char* strrecursion = (char*)calloc(16 * 1024, 1);
        s_recursion_str.set((void*)(strrecursion));

        XLoggerInfo info = *_info;
        info.level = kLevelFatal;

        char recursive_log[256] = {0};
        snprintf(recursive_log, sizeof(recursive_log), "ERROR!!! xlogger_appender Recursive calls!!!, count:%d", (int)recursion.Get());

        PtrBuffer tmp(strrecursion, 0, 16*1024);
        log_formater(&info, recursive_log, tmp);

        strncat(strrecursion, _log, 4096);
        strrecursion[4095] = '\0';

        ConsoleLog(&info,  strrecursion);
    } else {
        if (NULL != s_recursion_str.get()) {
            char* strrecursion = (char*)s_recursion_str.get();
            s_recursion_str.set(NULL);

            __writetips2file(strrecursion);
            free(strrecursion);
        }

        if (kAppednerSync == sg_mode)
            __appender_sync(_info, _log);
        else
            __appender_async(_info, _log);
    }
}

#define HEX_STRING  "0123456789abcdef"
static unsigned int to_string(const void* signature, int len, char* str) {
    char* str_p = str;
    const unsigned char* sig_p;

    for (sig_p = (const unsigned char*) signature;  sig_p - (const unsigned char*)signature < len; sig_p++) {
        char high, low;
        high = *sig_p / 16;
        low = *sig_p % 16;

        *str_p++ = HEX_STRING[(unsigned char)high];
        *str_p++ = HEX_STRING[(unsigned char)low];
        *str_p++ = ' ';
    }

    *str_p++ = '\n';

    for (sig_p = (const unsigned char*) signature;  sig_p - (const unsigned char*)signature < len; sig_p++) {
        *str_p++ = char(isgraph(*sig_p) ? *sig_p : ' ');
        *str_p++ = ' ';
        *str_p++ = ' ';
    }

    return (unsigned int)(str_p - str);
}

const char* xlogger_dump(const void* _dumpbuffer, size_t _len) {
    if (NULL == _dumpbuffer || 0 == _len) {
        //        ASSERT(NULL!=_dumpbuffer);
        //        ASSERT(0!=_len);
        return "";
    }

    SCOPE_ERRNO();

    if (NULL == sg_tss_dumpfile.get()) {
        sg_tss_dumpfile.set(calloc(4096, 1));
    } else {
        memset(sg_tss_dumpfile.get(), 0, 4096);
    }

    ASSERT(NULL != sg_tss_dumpfile.get());

    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    time_t sec = tv.tv_sec;
    tm tcur = *localtime((const time_t*)&sec);

    char forder_name [128] = {0};
    snprintf(forder_name, sizeof(forder_name), "%d%02d%02d", 1900 + tcur.tm_year, 1 + tcur.tm_mon, tcur.tm_mday);

    std::string filepath =  sg_logdir + "/" + forder_name + "/";

    if (!boost::filesystem::exists(filepath))
        boost::filesystem::create_directory(filepath);
    

    char file_name [128] = {0};
    snprintf(file_name, sizeof(file_name), "%d%02d%02d%02d%02d%02d_%d.dump", 1900 + tcur.tm_year, 1 + tcur.tm_mon, tcur.tm_mday,
             tcur.tm_hour, tcur.tm_min, tcur.tm_sec, (int)_len);
    filepath += file_name;

    FILE* fileid = fopen(filepath.c_str(), "wb");

    if (NULL == fileid) {
        ASSERT2(NULL != fileid, "%s, errno:(%d, %s)", filepath.c_str(), errno, strerror(errno));
        return "";
    }

    fwrite(_dumpbuffer, _len, 1, fileid);
    fclose(fileid);

    char* dump_log = (char*)sg_tss_dumpfile.get();
    dump_log += snprintf(dump_log, 4096, "\n dump file to %s :\n", filepath.c_str());

    int dump_len = 0;

    for (int x = 0; x < 32 && dump_len < (int)_len; ++x) {
        dump_log += to_string((const char*)_dumpbuffer + dump_len, std::min(int(_len) - dump_len, 16), dump_log);
        dump_len += std::min((int)_len - dump_len, 16);
        *(dump_log++) = '\n';
    }

    return (const char*)sg_tss_dumpfile.get();
}


static void get_mark_info(char* _info, size_t _infoLen) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    time_t sec = tv.tv_sec; 
    struct tm tm_tmp = *localtime((const time_t*)&sec);
    char tmp_time[64] = {0};
    strftime(tmp_time, sizeof(tmp_time), "%Y-%m-%d %z %H:%M:%S", &tm_tmp);
    snprintf(_info, _infoLen, "[%" PRIdMAX ",%" PRIdMAX "][%s]", xlogger_pid(), xlogger_tid(), tmp_time);
}

void appender_open(TAppenderMode _mode, const char* _dir, const char* _nameprefix) {
    assert(_dir);
    assert(_nameprefix);
    
    if (!sg_log_close) {
        __writetips2file("appender has already been opened. _dir:%s _nameprefix:%s", _dir, _nameprefix);
        return;
    }

    xlogger_SetAppender(&xlogger_appender);
    
    //mkdir(_dir, S_IRWXU|S_IRWXG|S_IRWXO);
    boost::filesystem::create_directories(_dir);
    tickcount_t tick;
    tick.gettickcount();
    __del_timeout_file(_dir);

    tickcountdiff_t del_timeout_file_time = tickcount_t().gettickcount() - tick;
    
    tick.gettickcount();

    char mmap_file_path[512] = {0};
    snprintf(mmap_file_path, sizeof(mmap_file_path), "%s/%s.mmap2", sg_cache_logdir.empty()?_dir:sg_cache_logdir.c_str(), _nameprefix);

    bool use_mmap = false;
    if (OpenMmapFile(mmap_file_path, kBufferBlockLength, sg_mmmap_file))  {
        sg_log_buff = new LogBuffer(sg_mmmap_file.data(), kBufferBlockLength, true);
        use_mmap = true;
    } else {
        char* buffer = new char[kBufferBlockLength];
        sg_log_buff = new LogBuffer(buffer, kBufferBlockLength, true);
        use_mmap = false;
    }

    if (NULL == sg_log_buff->GetData().Ptr()) {
        if (use_mmap && sg_mmmap_file.is_open())  CloseMmapFile(sg_mmmap_file);
        return;
    }


    AutoBuffer buffer;
    sg_log_buff->Flush(buffer);

    ScopedLock lock(sg_mutex_log_file);
    sg_logdir = _dir;
    sg_logfileprefix = _nameprefix;
    sg_log_close = false;
    appender_setmode(_mode);
    lock.unlock();
    
    char mark_info[512] = {0};
    get_mark_info(mark_info, sizeof(mark_info));

    if (buffer.Ptr()) {
        __writetips2file("~~~~~ begin of mmap ~~~~~\n");
        __log2file(buffer.Ptr(), buffer.Length());
        __writetips2file("~~~~~ end of mmap ~~~~~%s\n", mark_info);
    }

    tickcountdiff_t get_mmap_time = tickcount_t().gettickcount() - tick;


    char appender_info[728] = {0};
    snprintf(appender_info, sizeof(appender_info), "^^^^^^^^^^" __DATE__ "^^^" __TIME__ "^^^^^^^^^^%s", mark_info);

    xlogger_appender(NULL, appender_info);
    char logmsg[64] = {0};
    snprintf(logmsg, sizeof(logmsg), "del time out files time: %" PRIu64, (int64_t)del_timeout_file_time);
    xlogger_appender(NULL, logmsg);

    snprintf(logmsg, sizeof(logmsg), "get mmap time: %" PRIu64, (int64_t)get_mmap_time);
    xlogger_appender(NULL, logmsg);

    xlogger_appender(NULL, "MARS_URL: " MARS_URL);
    xlogger_appender(NULL, "MARS_PATH: " MARS_PATH);
    xlogger_appender(NULL, "MARS_REVISION: " MARS_REVISION);
    xlogger_appender(NULL, "MARS_BUILD_TIME: " MARS_BUILD_TIME);
    xlogger_appender(NULL, "MARS_BUILD_JOB: " MARS_TAG);

    snprintf(logmsg, sizeof(logmsg), "log appender mode:%d, use mmap:%d", (int)_mode, use_mmap);
    xlogger_appender(NULL, logmsg);

    BOOT_RUN_EXIT(appender_close);

}

void appender_open_with_cache(TAppenderMode _mode, const std::string& _cachedir, const std::string& _logdir, const char* _nameprefix) {
    assert(!_cachedir.empty());
    assert(!_logdir.empty());
    assert(_nameprefix);

    sg_logdir = _logdir;

    if (!_cachedir.empty()) {
        sg_cache_logdir = _cachedir;
        boost::filesystem::create_directories(_cachedir);
        __del_timeout_file(_cachedir);
        // "_nameprefix" must explicitly convert to "std::string", or when the thread is ready to run, "_nameprefix" has been released.
        Thread(boost::bind(&__move_old_files, _cachedir, _logdir, std::string(_nameprefix))).start_after(3 * 60 * 1000);
    }

    appender_open(_mode, _logdir.c_str(), _nameprefix);

}

void appender_flush() {
    sg_cond_buffer_async.notifyAll();
}

void appender_flush_sync() {
    if (kAppednerSync == sg_mode) {
        return;
    }

    ScopedLock lock_buffer(sg_mutex_buffer_async);
    
    if (NULL == sg_log_buff) return;

    AutoBuffer tmp;
    sg_log_buff->Flush(tmp);

    lock_buffer.unlock();

    if (tmp.Ptr())  __log2file(tmp.Ptr(), tmp.Length());

}

void appender_close() {
    if (sg_log_close) return;

    char mark_info[512] = {0};
    get_mark_info(mark_info, sizeof(mark_info));
    char appender_info[728] = {0};
    snprintf(appender_info, sizeof(appender_info), "$$$$$$$$$$" __DATE__ "$$$" __TIME__ "$$$$$$$$$$%s\n", mark_info);
    xlogger_appender(NULL, appender_info);

    sg_log_close = true;

    sg_cond_buffer_async.notifyAll();

    if (sg_thread_async.isruning())
        sg_thread_async.join();

    
    ScopedLock buffer_lock(sg_mutex_buffer_async);
    if (sg_mmmap_file.is_open()) {
        if (!sg_mmmap_file.operator !()) memset(sg_mmmap_file.data(), 0, kBufferBlockLength);

        CloseMmapFile(sg_mmmap_file);
    } else {
        delete[] (char*)((sg_log_buff->GetData()).Ptr());
    }

    delete sg_log_buff;
    sg_log_buff = NULL;
    buffer_lock.unlock();

    ScopedLock lock(sg_mutex_log_file);
    __closelogfile();
}

void appender_setmode(TAppenderMode _mode) {
    sg_mode = _mode;

    sg_cond_buffer_async.notifyAll();

    if (kAppednerAsync == sg_mode && !sg_thread_async.isruning()) {
        sg_thread_async.start();
    }
}

bool appender_get_current_log_path(char* _log_path, unsigned int _len) {
    if (NULL == _log_path || 0 == _len) return false;

    if (sg_logdir.empty())  return false;

    strncpy(_log_path, sg_logdir.c_str(), _len - 1);
    _log_path[_len - 1] = '\0';
    return true;
}

bool appender_get_current_log_cache_path(char* _logPath, unsigned int _len) {
    if (NULL == _logPath || 0 == _len) return false;
    
    if (sg_cache_logdir.empty())  return false;
    strncpy(_logPath, sg_cache_logdir.c_str(), _len - 1);
    _logPath[_len - 1] = '\0';
    return true;
}

void appender_set_console_log(bool _is_open) {
    sg_consolelog_open = _is_open;
}

void appender_set_log_files(int _max_size,int _max_files){
    sg_max_files = _max_files;
    sg_max_size = _max_size;
}


void appender_setExtraMSg(const char* _msg, unsigned int _len) {
    sg_log_extra_msg = std::string(_msg, _len);
}

bool appender_getfilepath_from_timespan(int _timespan, const char* _prefix, std::vector<std::string>& _filepath_vec) {
    //not support!
    return false;
}
