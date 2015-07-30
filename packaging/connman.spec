%bcond_with     connman_openconnect
%bcond_with     connman_openvpn
%bcond_with     connman_vpnd
%bcond_with     connman_ntp

Name:           connman
Version:        1.26
Release:        1
License:        GPL-2.0
Summary:        Connection Manager
Url:            http://connman.net
Group:          Network & Connectivity/Connection Management
Source0:        %{name}-%{version}.tar.gz
Source10:       40-connman-ntp.list
Source11:       connman-ntp.service
Source1001:     connman.manifest
BuildRequires: 	systemd-devel
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libiptc)
BuildRequires:  pkgconfig(xtables)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(gnutls)
%if %{with connman_openconnect}
BuildRequires:  openconnect
%endif
%if %{with connman_openvpn}
BuildRequires:  openvpn
%endif
BuildRequires:  readline-devel
%systemd_requires
Requires:       iptables

%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.

%if %{with connman_openconnect}
%package plugin-openconnect
Summary:        Openconnect Support for Connman
Requires:       %{name} = %{version}
Requires:       openconnect

%description plugin-openconnect
Openconnect Support for Connman.
%endif

%if %{with connman_openvpn}
%package plugin-openvpn
Summary:        Openvpn Support for Connman
Requires:       %{name} = %{version}
Requires:       openvpn

%description plugin-openvpn
OpenVPN support for Connman.
%endif

%if %{with connman_vpnd}
%package connman-vpnd
Summary:        VPN Support for Connman
BuildRequires:  %{name} = %{version}
Requires:       %{name} = %{version}

%description connman-vpnd
Provides VPN support for Connman
%endif

%package test
Summary:        Test Scripts for Connection Manager
Requires:       %{name} = %{version}
Requires:       dbus-python
Requires:       pygobject
Requires:       python-xml

%description test
Scripts for testing Connman and its functionality

%package devel
Summary:        Development Files for connman
Requires:       %{name} = %{version}

%description devel
Header files and development files for connman.

%prep
%setup -q
cp %{SOURCE1001} .

%build

chmod +x bootstrap
./bootstrap
%configure \
            --enable-threads \
            --enable-client \
            --enable-tizen-ext \
            --enable-pacrunner \
            --enable-wifi=builtin \
%if %{with connman_openconnect}
            --enable-openconnect \
%endif
%if %{with connman_openvpn}
            --enable-openvpn \
%endif
            --enable-test \
            --enable-loopback \
            --enable-ethernet \
            --with-systemdunitdir=%{_unitdir}

make %{?_smp_mflags}

%install
%make_install

%if %{with connman_ntp}
mkdir -p %{buildroot}/usr/lib/systemd/ntp-units.d
install -m644 %{SOURCE10} %{buildroot}/usr/lib/systemd/ntp-units.d
install -m644 %{SOURCE11} %{buildroot}%{_unitdir}
%install_service multi-user.target.wants connman-ntp.service
%endif

mkdir -p %{buildroot}%{_localstatedir}/lib/connman
cp resources/var/lib/connman/settings %{buildroot}%{_localstatedir}/lib/connman/settings

mkdir -p %{buildroot}%{_sysconfdir}/connman
cp src/main.conf %{buildroot}%{_sysconfdir}/connman/main.conf

%install_service multi-user.target.wants connman.service

%if %{with connman_vpnd}
%install_service multi-user.target.wants connman-vpn.service
%endif

%post
systemctl daemon-reload
systemctl restart connman.service
%if %{with connman_vpnd}
systemctl restart connman-vpn.service
%endif

%preun
systemctl stop connman.service
%if %{with connman_vpnd}
systemctl stop connman-vpn.service
%endif

%postun
systemctl daemon-reload

%docs_package

%files
%manifest %{name}.manifest
%license COPYING
%{_sbindir}/*
%{_libdir}/connman/plugins/*.so
%{_datadir}/man/*
%attr(600,root,root) %{_localstatedir}/lib/connman/settings
%config %{_sysconfdir}/connman/main.conf
%config %{_sysconfdir}/dbus-1/system.d/*
%{_unitdir}/connman.service
%{_unitdir}/multi-user.target.wants/connman.service
%if %{with connman_ntp}
%dir /usr/lib/systemd/ntp-units.d
%{_unitdir}/connman-ntp.service
%{_unitdir}/multi-user.target.wants/connman-ntp.service
/usr/lib/systemd/ntp-units.d/40-connman-ntp.list
%endif

%files test
%manifest %{name}.manifest
%{_libdir}/%{name}/test/*

%files devel
%manifest %{name}.manifest
%{_includedir}/connman/*.h
%{_libdir}/pkgconfig/*.pc

%if %{with connman_openconnect}
%files plugin-openconnect
%manifest %{name}.manifest
%{_unitdir}/connman-vpn.service
%{_libdir}/connman/plugins-vpn/openconnect.so
%{_libdir}/connman/scripts/openconnect-script
%{_datadir}/dbus-1/system-services/net.connman.vpn.service
%endif

%if %{with connman_openvpn}
%files plugin-openvpn
%manifest %{name}.manifest
%{_unitdir}/connman-vpn.service
%{_libdir}/%{name}/plugins-vpn/openvpn.so
%{_libdir}/%{name}/scripts/openvpn-script
%{_datadir}/dbus-1/system-services/net.connman.vpn.service
%endif

%if %{with connman_vpnd}
%files connman-vpnd
%manifest %{name}.manifest
%{_sbindir}/connman-vpnd
%{_unitdir}/connman-vpn.service
%{_unitdir}/multi-user.target.wants/connman-vpn.service
%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/scripts
%dir %{_libdir}/%{name}/plugins-vpn
%config %{_sysconfdir}/dbus-1/system.d/connman-vpn-dbus.conf
%{_datadir}/dbus-1/system-services/net.connman.vpn.service
%endif

%changelog
