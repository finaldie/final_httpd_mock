prefix = .
BIN_DIR_NAME = bin
CFG_DIR_NAME = etc

all:
	git submodule init
	git submodule update
	(cd flibs && make)
	cd src && make
check:
	cd src/test && make && make install && make run_test
install:
	-(test -d $(prefix)/$(BIN_DIR_NAME) || mkdir $(prefix)/$(BIN_DIR_NAME))
	-(test -d $(prefix)/$(CFG_DIR_NAME) || mkdir $(prefix)/$(CFG_DIR_NAME))
	cp src/httpd_mock $(prefix)/$(BIN_DIR_NAME)
	cp src/start_httpd_mock.sh $(prefix)/$(BIN_DIR_NAME)
	cp src/default_httpd_mock.cfg $(prefix)/$(CFG_DIR_NAME)/httpd_mock.cfg

.PHONY:clean
clean:
	(cd flibs && make clean)
	cd src && make clean
