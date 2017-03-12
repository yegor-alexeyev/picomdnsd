pkgname=picomdnsd
pkgver=5.5.1
pkgrel=5
pkgdesc="mdns responder implementation"
url='http://www.strongswan.org'
license=("custom")
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
  install -D mdnsd.service "$pkgdir/usr/lib/systemd/system/mdnsd.service"
  install -D mdnsd.socket "$pkgdir/usr/lib/systemd/system/mdnsd.socket"
  install -D LICENSE.txt "$pkgdir/usr/share/licenses/picomdnsd/LICENSE.txt"
}

