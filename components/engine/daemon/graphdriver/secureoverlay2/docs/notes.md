# Notes for Docker Security Feature

## Overview
The secureoverlay2 driver allows you to build and run docker images
containing _private encrypted layers_ layers which provide
Encrypted layers that will be protected by _dm-crypt_. Resulting images match 
the structure of standard images but, by necessity as no other driver supports
encryption, can be interpreted only by a daemon configured with our secureoverlay2 driver.

Once the image content is built, the security properties will be securely embedded
into the (per-layer) history objects contained in the docker image
meta-data, i.e., they are frozen by the image id once an image is built.

At container run time, the daemon will read security properties 
from the meta-data passing the required key dm-crypt.

## Usage

### Setup

Start daemon with --storage-driver secureoverlay2 (e.g., on ubuntu
with systemd you would have to modify the ExecStart option in
'/lib/systemd/system/docker.service').  Additionally, make sure that
you have enough loop-back device files, e.g., by running
  'for i in $(seq 1 255); do { dev="/dev/loop${i}"; if [ ! -e ${dev} ]; then echo "creating device $dev"; mknod $dev b 7 $i; chown root.disk $dev; chmod ug=rw,o-rwx $dev; fi } done;'


### Building secure images
New images are built by passing additional build options (see below)
which specify the security required for the new layers add in this
build.  Note no modification is required in the docker-files!

##### Docker build options
  * --security-opt crypt=<value>
   *value* can be alphanumeric password to lock the container image using which the image layers will be protected using encryption(dm-crypt).

### Distribution of secure docker images

Use docker pull/push work as before for image distribution: While the
docker daemons building and running secure images need to be modifed
with secureoverlay2 driver, it will work with "vanilla" docker
registry.  If encryption is involved, we assume there is an
out-of-band mechanism to pass the key-handles and corresponding keys.
Of course there must also be an authentic way to authentically
transmit an identifier to the image if it passed via an untrusted
registry. This could be simply the image-id or could make use of
docker trust/docker notary.


### Running secure docker images

The images will contain the security properties and key handles,
if encrypted, embeded in its meta-data (visible by running 'docker
history').  Hence you will run the image as you would any image. 

## External dependencies
#### Shell commands or external programs

* cryptsetup: used for encrypting the disk image for docker layer. Assumed to be in the standard path.

#### GO Packages

* [go-losetup](https://github.com/freddierice/go-losetup): used to loop mount the disk images for docker layer

