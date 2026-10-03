# Maintainer: soda92

pkgname=hash-id-git
_pkgname=hash-id
pkgver=2.0.0
pkgrel=1
pkgdesc="Identify hashes used to hash data and especially passwords (modernized Python 3 fork)"
arch=('any')
url="https://github.com/soda92/hash-id"
license=('AGPL-3.0-or-later')
depends=('python')
makedepends=('git' 'uv' 'python-installer')
checkdepends=('python-pytest')
provides=("$_pkgname")
conflicts=("$_pkgname")
source=("git+https://github.com/soda92/hash-id.git")
sha256sums=('SKIP')

pkgver() {
	cd "$srcdir/$_pkgname"
	git describe --long --tags 2>/dev/null | sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g' \
		|| printf '2.0.0.r%s.%s' "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
	cd "$srcdir/$_pkgname"
	# The uv_build backend ships inside uv itself, so the build needs no network.
	uv build --wheel
}

check() {
	cd "$srcdir/$_pkgname"
	PYTHONPATH=src python -m pytest
}

package() {
	cd "$srcdir/$_pkgname"
	python -m installer --destdir="$pkgdir" dist/*.whl

	install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
	install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
