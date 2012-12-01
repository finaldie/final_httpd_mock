Description:

    A http mock service, for performance testing, debugging or something else.
    It support 3 types of response:
        1. specific length response
        2. chunked response
        3. mix type ( contain two types above )
    NOTE: The response content is all filled by 'F'
    NOTE: It require kernel version greater than 2.6.31

How to Run:

    1. make
    2. make install
    3. cd bin && ./httpd_mock -c ../etc/httpd_mock.cfg
