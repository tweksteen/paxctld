Name: paxctld
Version: 1.0
Release: 1%{?dist}
Summary: PaX flags maintenance daemon
Group: admin
License: GPLv2
Requires(post): chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts
Requires(postun): initscripts
URL: https://grsecurity.net
Source: https://grsecurity.net/paxctld-1.0.tgz

%description
paxctld is a daemon that automatically applies PaX flags to binaries on
the system.  These flags are applied via user extended attributes and are
refreshed on any update to the binaries specified in its configuration file.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 rpm/paxctld.init $RPM_BUILD_ROOT/etc/rc.d/init.d/paxctld

%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add paxctld
/sbin/service paxctld start >/dev/null 2>&1

%preun
if [ $1 -eq 0 ] ; then
    /sbin/service paxctld stop >/dev/null 2>&1
    /sbin/chkconfig --del paxctld
fi

%postun
if ["$!" -ge "1" ] ; then
    /sbin/service paxctld condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root)
%attr(0755,root,root) /sbin/paxctld
%attr(0644,root,root) %{_mandir}/man8/paxctld.8.gz
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/paxctld.conf
%attr(0755,root,root) %config %{_sysconfdir}/rc.d/init.d/paxctld
%doc

%changelog
* Wed Dec 17 2014 Brad Spengler <spender@grsecurity.net> 1.0
- Initial release
