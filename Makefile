prefix = .
BIN_DIR_NAME = bin
CFG_DIR_NAME = etc

FLIBS = flibs
FLIBSDEV = $(FLIBS)/final_libraries
HTTP_PARSER = http-parser
INC = include
LIB = lib64
TESTS = tests
SRC = src

all: prepare flibs http_parser
	cd $(SRC) && make

prepare:
	test -d $(INC) || mkdir $(INC)
	test -d $(LIB) || mkdir $(LIB)

flibs:
	cd $(FLIBS) && make -s all64
	cp -R $(FLIBSDEV)/$(INC)/* $(INC)
	cp -R $(FLIBSDEV)/$(LIB)/* $(LIB)

http_parser:
	cd $(HTTP_PARSER) && make package
	cp $(HTTP_PARSER)/http_parser.h $(INC)
	cp $(HTTP_PARSER)/libhttp_parser.a $(LIB)

check:
	cd $(TESTS) && make && make check

install:
	test -d $(prefix)/$(BIN_DIR_NAME) || mkdir $(prefix)/$(BIN_DIR_NAME)
	test -d $(prefix)/$(CFG_DIR_NAME) || mkdir $(prefix)/$(CFG_DIR_NAME)
	cp $(SRC)/httpd_mock $(prefix)/$(BIN_DIR_NAME)
	cp $(SRC)/start_httpd_mock.sh $(prefix)/$(BIN_DIR_NAME)
	cp $(SRC)/default_httpd_mock.cfg $(prefix)/$(CFG_DIR_NAME)/httpd_mock.cfg

clean: flibs_clean http_parser_clean
	rm -rf $(BIN_DIR_NAME) $(CFG_DIR_NAME) $(INC) $(LIB)
	cd $(TESTS) && make clean
	cd $(SRC) && make clean

flibs_clean:
	cd $(FLIBS) && make -s clean

http_parser_clean:
	cd $(HTTP_PARSER) && make clean

.PHONY: all clean prepare flibs http_parser check install flibs_clean http_parser_clean
