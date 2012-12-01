prefix = .
BIN_DIR_NAME = bin
CFG_DIR_NAME = etc

all:
	(cd flibs && make)
	cd src && make

install:
	-(test -d $(prefix)/$(BIN_DIR_NAME) || mkdir $(prefix)/$(BIN_DIR_NAME))
	-(test -d $(prefix)/$(CFG_DIR_NAME) || mkdir $(prefix)/$(CFG_DIR_NAME))
	mv src/httpd_mock $(prefix)/$(BIN_DIR_NAME)
	mv src/default_httpd_mock.cfg $(prefix)/$(CFG_DIR_NAME)/httpd_mock.cfg

.PHONY:clean
clean:
	(cd flibs && make clean)
	cd src && make clean
