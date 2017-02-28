pkgname=picomdnsd
pkgver=5.5.1
pkgrel=5
pkgdesc="open source IPsec implementation"
url='http://www.strongswan.org'
license=("GPL")
arch=('i686' 'x86_64')
srcdir=.



build() {
  cd ..
  make

}

package() {
#  cd "${srcdir}/${pkgname}-${pkgver}"
  cd ..
  install -D picomdnsd "$pkgdir/usr/bin/picomdnsd"
  install -D mdnsd "$pkgdir/usr/bin/mdnsd"
  install -D mdnsd.service "$pkgdir/usr/lib/systemd/system/mdnsd.service"
}

