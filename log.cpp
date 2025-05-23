#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <ostream>
#include <sstream>

#include "log.h"
#include "time.h"


logger::logger()
{
}

logger::~logger()
{
}

void logger::set_loglevel(const loglevel_t ll)
{
	this->ll = ll;
}

void logger::dolog(const logger::loglevel_t ll, const char *const file, const void *const p, const char *const function, const char *const fmt, ...)
{
	us_time_t now        = get_us();
	char     *log_buffer = nullptr;

	va_list ap;
	va_start(ap, fmt);
	vasprintf(&log_buffer, fmt, ap);
	va_end(ap);

	char  *time_buffer = nullptr;
        time_t t_now       = now / 1000000;
        tm     tm { };
	if (!localtime_r(&t_now, &tm))
		asprintf(&time_buffer, "localtime_r failed");
	else {
		asprintf(&time_buffer, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, int(now % 1000000));
	}

	std::ostringstream oss;
	if (p)
		oss << time_buffer << " " << file << " [" << p << "] [" << function << "] " << log_buffer << std::endl;
	else
		oss << time_buffer << " " << file << " [" << function << "] " << log_buffer << std::endl;
	std::string buffer { oss.str() };

	std::ofstream fh("logfile.txt", std::ios::out | std::ios::app);
	fh << buffer;
	fh.close();

	std::cout << buffer;

	free(time_buffer);

	free(log_buffer);
}

logger log_;
