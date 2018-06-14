# Update the list and install the dependencies for libressl
sudo apt-get update
sudo apt-get install automake autoconf git libtool perl

# Clone the libressl from Github 
git clone https://github.com/libressl-portable/portable.git libressl

# Prepare the source tree
cd libressl && ./autogen.sh

# Configure the source tree and compile the libressl
sudo ./configure --prefix="${HOME}/opt/libressl" && make -j

# Install the libressl under ${HOME}/opt/libressl
sudo make install

# Write the library to linked library config file
echo `printenv HOME`/opt/libressl | sudo tee /etc/ld.so.conf.d/libressl.conf
sudo ldconfig