# MINDS - Minnesota Intrusion Detection System.

Repository Maintained by:
- Varun Chandola
- chandola@buffalo.edu


For detailed installation and operation instructions, refer to [MINDS manual](tree/docs/manual.pdf).
### To install flows-tools:
cd $MINDSDIR/src
tar -zxvf flow-tools-0.68.2-rc5.tar.gz
cd flow-tools-0.68.2-rc5
./configure --prefix $CONFIGSITE
make install
### To install pcap:
tar -zxvf libpcap-0.8.1.tar.gz
cd libpcap-0.8.1
./configure --prefix $CONFIGSITE
make
make install
### To install xmlparser:
cd  $MINDSDIR/src
tar -zxvf xmlparser-1.0.tar.gz
cd xmlparser-1.0
./configure --prefix $CONFIGSITE
make install
### To install minds:
cd $MINDSDIR
./configure --prefix $CONFIGSITE
make install

Refer to the manual for detailed instructions.
