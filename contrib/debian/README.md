
Debian
====================
This directory contains files used to package idapayd/idapay-qt
for Debian-based Linux systems. If you compile idapayd/idapay-qt yourself, there are some useful files here.

## idapay: URI support ##


idapay-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install idapay-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your idapay-qt binary to `/usr/bin`
and the `../../share/pixmaps/idapay128.png` to `/usr/share/pixmaps`

idapay-qt.protocol (KDE)

