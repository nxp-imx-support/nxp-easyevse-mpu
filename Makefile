LIB_PATH=/usr/lib
COMMON_PATH=common/
SERVER_PATH=server/
NFC_PATH=nfc/
GUI_PATH=gui/
METER_PATH=meter/
CLOUD_PATH=cloud/

all: dir binary

clean:
	rm -rf release/

dir:
	if [ ! -d "release" ]; then \
		mkdir release; \
	fi
	
	if [ ! -f "release/evse.conf" ]; then \
		cp evse.conf release/; \
	fi

binary: server_app meter_app nfc_app 

server_app:
	${CC} ${COMMON_PATH}/utils.c ${COMMON_PATH}/comms.c ${COMMON_PATH}/logger.c ${SERVER_PATH}/server.c -lcjson -o release/SERVER

meter_app:
	${CC} ${METER_TARGET} ${COMMON_PATH}/utils.c ${COMMON_PATH}/comms.c ${COMMON_PATH}/logger.c ${METER_PATH}/meter_app.c -lcjson -o release/METER

nfc_app:
	${CC} ${COMMON_PATH}/utils.c ${COMMON_PATH}/comms.c ${COMMON_PATH}/logger.c ${NFC_PATH}/nfc_api.c ${NFC_PATH}/nfc_app.c  ${WORKDIR}/recipe-sysroot/usr/lib/libtoolnfc.a -L${LIB_PATH} -l:libnfc_nci_linux-1.so.0 -lcjson -o release/NFC

