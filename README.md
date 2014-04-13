[![Build Status](https://travis-ci.org/finaldie/final_httpd_mock.svg?branch=0.2)](https://travis-ci.org/finaldie/final_httpd_mock)

Lastest Versions:

    +--------+--------------------+------------+--------------------------------------+
    | Branch | Lastest Stable Tag |  Released  | Description                          |
    +--------+--------------------+------------+--------------------------------------+
    |  0.2   | 0.2.1              | 2013-10-25 | Using new timer service framework    |
    +--------+--------------------+------------+--------------------------------------+
    |  0.1   | 0.1.5              | 2013-07-10 | 4 basic types of response simulation |
    +--------+--------------------+------------+--------------------------------------+

Description:

    A http mock service, for performance testing, debugging or something else.
    It support 4 types of response:
        1. specific length response
        2. chunked response
        3. mix type ( contain two types above )
        4. replay pcap file data, to simulate the real server response
    NOTE: The response content is all filled by 'F'
    NOTE: It require kernel version greater than 2.6.31
    NOTE: It require libpcap library

How to Run:

    1. ./bootstrap
    2. make
    3. make install
    4. cd bin && ./httpd_mock -c ../etc/httpd_mock.cfg

ChangeLog:

    0.2.1 2013-10-25
      Upgrade to new timer service
    0.2.0 2013-09-05
      Issue #9: Upgrade flibs to 0.4.x
    0.1.5 2013-09-04
      Cleanup the source code environment
    0.1.4 2013-07-29
      Correct the content-length value in non-chunked response
    0.1.3 2013-07-10
      Issue #6: Support deal with muddled tcp/ip package and retransmit package
    0.1.2 2013-04-27
      Fix coredump issue when handle the un-http response header format data
    0.1.1 2013-04-08
      Support loading pcap file, to simulate the real server response
    0.1.0 2012-12-07
      basic framework, support 3 types response:
      * specific length response
      * chunked response
      * mix type
