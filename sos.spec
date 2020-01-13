%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Summary: A set of tools to gather troubleshooting information from a system
Name: sos
Version: 3.2
Release: 63%{?dist}.4
Group: Applications/System
Source0: https://fedorahosted.org/releases/s/o/sos/%{name}-%{version}.tar.gz
License: GPLv2+
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildArch: noarch
Url: http://fedorahosted.org/sos
BuildRequires: python-devel
BuildRequires: gettext
Requires: libxml2-python
Requires: bzip2
Requires: xz
Patch0: sos-six-compat.patch
Patch1: sos-call-rhsm-debug-with-no-subscriptions.patch
Patch2: sos-powerpc-allow-powerpc-plugin-to-run-on-ppc64le.patch
Patch3: sos-ovirt_hosted_engine-fix-exception-when-force-enabled.patch
Patch4: sos-corosync-add-postprocessing-for-corosync-objctl.patch
Patch5: sos-add-support-for-tomcat7.patch
Patch6: sos-obtain-mysql-password-from-env.patch
Patch7: sos-sosreport-fix-archive-permissions-regression.patch
Patch8: sos-fix-kpatch-force-enabled.patch
Patch9: sos-disable-the-zip-compression-type.patch
Patch10: sos-navicli-catch-unreadable-stdin.patch
Patch11: sos-docs-update-man-page-for-new-options.patch
Patch12: sos-sos-unicode-use-errors-ignore.patch
Patch13: sos-mysql-fix-command-line-dbpass-handling.patch
Patch14: sos-anaconda-make-useradd-password-regex-tolerant.patch
Patch15: sos-sosreport-catch-oserror-in-execute.patch
Patch16: sos-sosreport-do-not-make-logging-calls-after-oserror.patch
Patch17: sos-plugin-limit-names-to-pc_name_max.patch
Patch18: sos-squid-collect-var-log-squid.patch
Patch19: sos-sosreport-log-plugin-exceptions-to-file.patch
Patch20: sos-ctdb-fix-redhatplugin-tagging-use.patch
Patch21: sos-sosreport-fix-silent-exception-handling.patch
Patch22: sos-mysql-test-for-boolean-values.patch
Patch23: sos-mysql-improve-dbuser-dbpass-handling.patch
Patch24: sos-bz1144525-six-six-six.patch
Patch25: sos-bz1144525-rhel6-tmp-policy.patch
Patch26: sos-bz1171186-add_luci_package_fixed_lockdumps.patch
Patch27: sos-bz1172880-puppet-adding-new-plugin-for-puppet.patch
Patch28: sos-bz1183770-block-use-sectors-for-output.patch
Patch29: sos-bz1135290-skip_generic_resource_collection_with_foreman_plugin_and_dropped_katello_plugin.patch
Patch30: sos-bz1166874-openshift-collect_additional_config_files.patch
Patch31: sos-bz1165878-activemq-honour_all_logs_and_get_config.patch
Patch32: sos-bz1190723-cluster-no-dir-crm_tool.patch
Patch33: sos-bz1203330-openshift_scrub_config_files.patch
Patch34: sos-bz1206661-test_nmcli_status_before_using_output.patch
Patch35: sos-bz1209455-fix_ip_addr_collection.patch
Patch36: sos-bz1174186-tuned_collect_configs.patch
Patch37: sos-bz1203330-openshift_scrub_plugin_config_files.patch
Patch38: sos-bz1209442-mysql_collect_log_file.patch
Patch39: sos-bz1206581-cluster_scrub_crm_report.patch
Patch40: sos-bz1206661-nmcli_options.patch
Patch41: sos-bz1206661-nmcli_status_err.patch
Patch42: sos-bz1234226-ovirt-collect-engine-and-domain-info.patch
Patch43: sos-bz1263887-only_run_brctl_if_bridge_module_loaded.patch
Patch44: sos-bz1274710-qpid_missing_comma.patch
Patch45: sos-bz1195606-add-plugins-SAP-NetWeaver-and-SAP-HANA.patch
Patch46: sos-bz1209342-capture-efibootmgr-output.patch
Patch47: sos-bz1269954-add_timeout_hpasm_plugin.patch
Patch48: sos-policies-PackageManager-timeout.patch
Patch49: sos-bz1232945-sos-ticket-number-name-params.patch
Patch50: sos-bz1286933-sosreport-prepare-report-in-a-private-subdirectory.patch
Patch51: sos-bz1274729-powerpc_missing_commas.patch
Patch52: sos-bz1253144-add_plugin_IprConfig.patch
Patch53: sos-bz1286933-report_correct_final_path_with_--build.patch
Patch54: sos-bz1195606-check_sapnw_has_instances_check.patch
Patch55: sos-bz1276652-support_glob_expansion_in_command_arguments.patch
Patch56: sos-bz1267677-move_extra_rpm_fields_to_separate_file.patch
Patch57: sos-bz1227462-obfuscate_ldap_bind_passwords.patch
Patch58: sos-bz1289558-add_output_of_multipathd_show_config.patch
Patch59: sos-bz1232940-remove_hand_rolled_compression_shell_out.patch
Patch60: sos-bz1203947-improvements_to_ipa.patch
Patch61: sos-bz1276262-blacklist_cisco_cdp_paths.patch
Patch62: sos-bz1275202-processor-cpufreq-info.patch
Patch63: sos-bz1310183-check_compress_binary_exists.patch
Patch64: sos-bz1283682-add_DUMP_MODULES_output_from_httpd.patch
Patch65: sos-bz1293510-capture_ip_-s_link_output.patch
Patch66: sos-bz1324535-lvm2_lvmdump_does_not_collect_any_data.patch
Patch67: sos-bz1338549-obfuscate_password_in_AAA_profile_files.patch
Patch68: sos-bz1368547-add_plugins_npm_and_nodejs.patch
Patch69: sos-bz1317035-add_cpuid_output_to_sosreport.patch
Patch70: sos-bz1346042-sosreport_does_not_collect_all_tomcat_logs.patch
Patch71: sos-bz1299892-html_reports_not_generated.patch
Patch72: sos-bz1409822-processor_plugin_missing_comma.patch
Patch73: sos-bz1416079-add-files-to-forbidden-list.patch
Patch74: sos-bz1451784-check_module_version_and_do_ipv6.patch
Patch75: sos-bz1427589-pcs_config_sanitize.patch
Patch76: sos-bz1489041-dont_always_load_iptable_filter.patch
Patch77: sos-bz1506596-get_pkg_list_without_timeout.patch
Patch78: sos-bz1506596-handle_missing_filesystem_pkg.patch
Patch79: sos-bz1481910-logging_shutdown_after_archive.patch
Patch80: sos-bz1439943-spacewalk-debug_timeout.patch
Patch81: sos-bz1496288-pm_release_field.patch
Patch82: sos-bz1496288-skip_spacewalk-backend_if_old.patch
Patch83: sos-bz1496288-archive_no_timeout.patch
Patch84: sos-bz1567054-Ctrl_C_propagate.patch
Patch85: sos-bz1599234-force_decoding_if_bytes.patch
Patch86: sos-bz1599234-reporting_utf8.patch
Patch87: sos-bz1596496-CDS_detection.patch
Patch88: sos-bz1567063-dont_collect_pkcs11_inspect.patch
Patch89: sos-bz1667018-dont_collect_ssl-build.patch
Patch90: sos-bz1753166-priv_keys_httpd.patch

# Branding patch
Patch1000: eurolinux.patch
%description
Sos is a set of tools that gathers information about system
hardware and configuration. The information can then be used for
diagnostic purposes and debugging. Sos is commonly used to help
support technicians and developers.

%prep
%setup -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch9 -p1
%patch10 -p1
%patch11 -p1
%patch12 -p1
%patch13 -p1
%patch14 -p1
%patch15 -p1
%patch16 -p1
%patch17 -p1
%patch18 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1
%patch22 -p1
%patch23 -p1
%patch24 -p1
%patch25 -p1
%patch26 -p1
%patch27 -p1
%patch28 -p1
%patch29 -p1
%patch30 -p1
%patch31 -p1
%patch32 -p1
%patch33 -p1
%patch34 -p1
%patch35 -p1
%patch36 -p1
%patch37 -p1
%patch38 -p1
%patch39 -p1
%patch40 -p1
%patch41 -p1
%patch42 -p1
%patch43 -p1
%patch44 -p1
%patch45 -p1
%patch46 -p1
%patch47 -p1
%patch48 -p1
%patch49 -p1
%patch50 -p1
%patch51 -p1
%patch52 -p1
%patch53 -p1
%patch54 -p1
%patch55 -p1
%patch56 -p1
%patch57 -p1
%patch58 -p1
%patch59 -p1
%patch60 -p1
%patch61 -p1
%patch62 -p1
%patch63 -p1
%patch64 -p1
%patch65 -p1
%patch66 -p1
%patch67 -p1
%patch68 -p1
%patch69 -p1
%patch70 -p1
%patch71 -p1
%patch72 -p1
%patch73 -p1
%patch74 -p1
%patch75 -p1
%patch76 -p1
%patch77 -p1
%patch78 -p1
%patch79 -p1
%patch80 -p1
%patch81 -p1
%patch82 -p1
%patch83 -p1
%patch84 -p1
%patch85 -p1
%patch86 -p1
%patch87 -p1
%patch88 -p1
%patch89 -p1
%patch90 -p1

#Branding patch
%patch1000 -p1

%build
make

%install
rm -rf ${RPM_BUILD_ROOT}
make DESTDIR=${RPM_BUILD_ROOT} install
%find_lang %{name} || echo 0

%clean
rm -rf ${RPM_BUILD_ROOT}

%files -f %{name}.lang
%defattr(-,root,root,-)
%{_sbindir}/sosreport
%{_datadir}/%{name}
%{python_sitelib}/*
%{_mandir}/man1/*
%{_mandir}/man5/*
%doc AUTHORS README.md LICENSE
%config(noreplace) %{_sysconfdir}/sos.conf

%changelog
* Wed Nov 20 2019 Aleksander Baranowski <aleksander.baranowski@euro-linux.com>
  - Pull from upstream
   -> [satellite] dont collect apache and squid data
   -> Resolves: bz1753166

* Wed Feb 27 2019 Aleksander Baranowski <aleksander.baranowski@euro-linux.com> 3.2-63.3
- Pull from upstream:
  [smartcard] Stop collecting pkcs11_inspect debug
  Resolves: bz1567063
  [satellite] don't collect /root/ssl-build
  Resolves: bz1667018
  [rhui] Fix detection of CDS for RHUI3
  Resolves: bz1596496
  [archive] Force decoding if content is bytes
  [reporting] deal with UTF-8 characters
  Resolves: bz1599234

* Mon Jul 23 2018 Aleksander Baranowski <aleksander.baranowski@euro-linux.com> 3.2-63
- Pull from upstream: 
  [archive] compress tarball without a timeout
  Resolves: bz1439943
  [policies] stop execution on Ctrl+C during user input
  Resolves: bz1567054
  [policies/redhat] assume pre-usrmove
  Resolves: bz1506596
  [sosreport] close unused file descriptors of temp.files
  Resolves: bz1481910
  [satellite] skip spacewalk-debug if spacewalk-backend too old
  Resolves: bz1496288
  [satellite] increase timeout of spacewalk-debug to 15minutes
  Resolves: bz1439943
  [sosreport] logging has to be shut down after the final archive is created
  Resolves: bz1481910
  [policies] get package list without a timeout
  [policies/redhat] make missing 'filesystem' package non-fatal
  Resolves: bz1506596
  [networking] call iptables -L only when iptable_filter module is loaded
  Resolves: bz1489041
  [networking] iptables: check module version and do ipv6
  Resolves: bz1451784
  [cluster] Scrub passwords in pcs config
  Resolves: bz1427589

* Mon Dec  4 2017 Aleksander Baranowski <aleksander.baranowski@euro-linux.com> 3.2-55.1
- Branding patch for EuroLinux.

* Fri Oct 20 2017 Filip Krska <fkrska@redhat.com> = 3.2-54.el6_9.1
  [networking] iptables: check module version and do ipv6
  Resolves: bz1451784
  [cluster] Scrub passwords in pcs config
  Resolves: bz1427589


* Thu Feb 16 2017 Shane Bradley <sbradley@redhat.com> = 3.2-54
  [cluster] Add ricci file to forbidden list
  Resolves: bz1416079

* Thu Feb 09 2017 Shane Bradley <sbradley@redhat.com> = 3.2-53
  [ldap] Add files to forbidden list
  Resolves: bz1416079

* Wed Feb 08 2017 Shane Bradley <sbradley@redhat.com> = 3.2-52
  [smartcard/cluster/ds/openswan] Add files to forbidden list
  Resolves: bz1416079

* Fri Jan 06 2017 Shane Bradley <sbradley@redhat.com> = 3.2-51
  [processor] missing comma between cpufreq-info and cpuid
  Resolves: bz1409822

* Fri Dec 09 2016 Shane Bradley <sbradley@redhat.com> = 3.2-50
- [ovirt] Obfuscate password in AAA profile files.
  Resolves: bz1338549

* Wed Oct 19 2016 Shane Bradley <sbradley@redhat.com> = 3.2-49
- [sosreport] The reports were not generated.
  Resolves: bz1299892

- [npm/nodejs] Add plugins npm and nodejs.
  The patch contained plugin classes that are not in rhel-6
  which were removed.
  Resolves: bz1368547

* Wed Oct 19 2016 Shane Bradley <sbradley@redhat.com> = 3.2-48
- [tomcat] Not all log files are collected.
  Resolves: bz1346042

* Wed Oct 19 2016 Shane Bradley <sbradley@redhat.com> = 3.2-47
- [processor] Add cpuid output to sosreport.
  Resolves: bz1317035

* Mon Oct 17 2016 Shane Bradley <sbradley@redhat.com> = 3.2-46
- [npm/nodejs] Add plugins npm and nodejs.
  Resolves: bz1368547

* Mon Oct 17 2016 Shane Bradley <sbradley@redhat.com> = 3.2-45
- [ovirt] Obfuscate password in AAA profile files.
  Resolves: bz1338549

* Mon Oct 17 2016 Shane Bradley <sbradley@redhat.com> = 3.2-44
- [lvm2] lvm2 lvmdump does not collect any data.
  Resolves: bz1324535

* Mon Oct 17 2016 Shane Bradley <sbradley@redhat.com> = 3.2-43
- [networking] Capture ip -s link output.
  Resolves: bz1293510

* Mon Oct 17 2016 Shane Bradley <sbradley@redhat.com> = 3.2-42
- [apache] Collect list of modules
  Resolves: bz1283682

* Wed Mar 16 2016 Shane Bradley <sbradley@redhat.com> = 3.2-40
- [processor] Capture output of cpufreq-info
  Resolves: bz1275202
- [archive] Check that compress utility exists
  Resolves: bz1310183

* Fri Feb 05 2016 Shane Bradley <sbradley@redhat.com> = 3.2-39
- [ipa] Improvements to plugin.
  Resolves: bz1203947
- [networking] Blacklist Cisco CDP paths
  Resolves: bz1276262

* Tue Feb 02 2016 Shane Bradley <sbradley@redhat.com> = 3.2-38
- [openshift] Obfuscate LDAP bind passwords
  Resolves: bz1227462
- [multipath] Add output of "multipathd show config" in sosreport
  Resolves: bz1289558
- [archive] remove hand-rolled compression shell out.
  Resolves: bz1232940

* Mon Feb 01 2016 Shane Bradley <sbradley@redhat.com> = 3.2-37
- [utilities] Support glob expansion in command arguments
  Resolves: bz1276652
- [rpm] Move extra rpm fields to a separate file
  Resolves: bz1267677

* Thu Jan 21 2016 Shane Bradley <sbradley@redhat.com> = 3.2-36
- [sapnw] Check if there are SAP Net Weaver instances.
  Resolves: bz1195606

* Wed Jan 13 2016 Shane Bradley <sbradley@redhat.com> = 3.2-35
- [IprConfig] New plugin for IBM Power RAID storage adapter
  configuration.
  Resolves: bz1253144

* Mon Jan 11 2016 Shane Bradley <sbradley@redhat.com> = 3.2-34
- [powerpc] Missing commas in list of files to capture.
  Resolves: bz1274729

* Tue Jan 05 2016 Shane Bradley <sbradley@redhat.com> = 3.2-33
- [sosreport] prepare report in a private subdirectory
  Resolves: bz1286933

* Tue Dec 15 2015 Shane Bradley <sbradley@redhat.com> = 3.2-32
- [general] Better handling of --name and --ticket-number options.
  Resolves: bz1232945
- [policies] run PackageManager query_command under timeout

* Tue Dec 15 2015 Shane Bradley <sbradley@redhat.com> = 3.2-31
- [hpasm] Add timeout.
  Resolves: bz1269954

* Wed Dec 09 2015 Shane Bradley <sbradley@redhat.com> = 3.2-30
- [saphana/sapnw] Add plugins for SAP NetWeaver and SAP HANA.
  Resolves: bz1195606
- [boot] Capture output for efibootmgr.
  Resolves: bz1209342

* Tue Dec 08 2015 Shane Bradley <sbradley@redhat.com> = 3.2-29
- [networking] The commmand brctl will only be ran if bridge module loaded.
  Resolves: 1263887
- [qpid] Added missing comma in list of command outputs to capture.
  Resolves: 1274710

* Mon Jun 22 2015 Shane Bradley <sbradley@redhat.com> = 3.2-28
- [ovirt] Collect engine tuneables and domain information.
  Resolves: bz1234226

* Thu Jun 18 2015 Shane Bradley <sbradley@redhat.com> = 3.2-27
- [networking] nmcli status is obtained from the output
  Resolves: bz1206661

* Thu May 21 2015 Shane Bradley <sbradley@redhat.com> = 3.2-26
- [cluster] Scrub password from crm_report data.
  Resolves: bz1206581
- [networking] Use the correct options for nmcli.
  Resolves: bz1206661

* Mon Apr 27 2015 Shane Bradley <sbradley@redhat.com> = 3.2-25
- [mysql] Collect log file by default.
  Resolves: bz1209442

* Fri Apr 17 2015 Shane Bradley <sbradley@redhat.com> = 3.2-24
- [openshift] Scrub passwords from plugin config files.
  Resolves: bz1203330

* Thu Apr 16 2015 Shane Bradley <sbradley@redhat.com> = 3.2-23
- [tuned] Collect additional configurations files and profiles.
  Resolves: bz1174186

* Tue Apr 14 2015 Shane Bradley <sbradley@redhat.com> = 3.2-22
- [networking] Fix "ip addr" collection.
  Resolves: bz1209455

* Tue Mar 31 2015 Shane Bradley <sbradley@redhat.com> = 3.2-21
- [networking] test nmcli status before using output
  Resolves: bz1206661

* Thu Mar 26 2015 Shane Bradley <sbradley@redhat.com> = 3.2-20
- [openshift] Scrub passwords from config files.
  Resolves: bz1203330

* Wed Mar 11 2015 Shane Bradley <sbradley@redhat.com> = 3.2-19
- [cluster] Ensure cluster sets 'make' to False when calling get_cmd_output_path().
  Resolves: bz1190723

* Mon Mar 9 2015 Shane Bradley <sbradley@redhat.com> = 3.2-18
- [openshift] Collect additional config files.
  Resolves: bz1166874
- [activemq] Honour all_logs and get config on RHEL.
  Resolves: bz1165878

* Mon Mar 2 2015 Bryn M. Reeves <bmr@redhat.com> = 3.2-17
- [policy/redhat] use /tmp as default temporary directory
- [global] remove dependency on python-six
  Resolves: bz1144525

* Mon Mar 2 2015 Shane Bradley <sbradley@redhat.com> = 3.2-16
- [cluster] Added package luci and fix lockdumps capturing.
  Resolves: bz1171186
- [puppet] Adding new plugin for puppet
  Resolves: bz1172880
- [block] parted will use sector units instead of human units.
  Resolves: bz1086537
- [foreman] Added option to prevent generic resource collection with foreman plugin. Remove the plugin katello since data collection done by foreman-debug.
  Resolves: bz1135290

* Wed Feb 18 2015 Bryn M. Reeves <bmr@redhat.com> = 3.2-15
- [global] update el6 to upstream 3.2 release
  Resolves: bz1144525
- [global] sync 3.2-15.el6 with RHEL-7.1
  Resolves: bz1144525

* Tue Jan 20 2015 Bryn M. Reeves <bmr@redhat.com> = 3.2-14
- [mysql] test for boolean values in dbuser and dbpass
- [mysql] improve handling of dbuser, dbpass and MYSQL_PWD

* Mon Jan 19 2015 Bryn M. Reeves <bmr@redhat.com> = 3.2-12
- [plugin] limit path names to PC_NAME_MAX
- [squid] collect files from /var/log/squid
- [sosreport] log plugin exceptions to a file
- [ctdb] fix collection of /etc/sysconfig/ctdb
- [sosreport] fix silent exception handling

* Tue Jan 13 2015 Bryn M. Reeves <bmr@redhat.com> = 3.2-11
- [sosreport] do not make logging calls after OSError
- [sosreport] catch OSError exceptions in SoSReport.execute()
- [anaconda] make useradd password regex tolerant of whitespace

* Tue Dec 23 2014 Bryn M. Reeves <bmr@redhat.com> = 3.2-10
- [mysql] fix handling of mysql.dbpass option

* Wed Dec 17 2014 Bryn M. Reeves <bmr@redhat.com> = 3.2-9
- [navicli] catch exceptions if stdin is unreadable
- [docs] update man page for new options
- [sosreport] make all utf-8 handling user errors=ignore

* Tue Dec 09 2014 Bryn M. Reeves <bmr@redhat.com> = 3.2-8
- [kpatch] do not attempt to collect data if kpatch is not installed
- [archive] drop support for Zip archives

* Thu Oct 30 2014 Bryn M. Reeves <bmr@redhat.com> = 3.2-7
- [sosreport] fix archive permissions regression

* Mon Oct 20 2014 Bryn M. Reeves <bmr@redhat.com> = 3.2-6
- [tomcat] add support for tomcat7 and default log size limits
- [mysql] obtain database password from the environment

* Wed Oct 15 2014 Bryn M. Reeves <bmr@redhat.com> = 3.2-5
- [corosync] add postprocessing for corosync-objctl output
- [ovirt_hosted_engine] fix exception when force-enabled

* Thu Oct 02 2014 Bryn M. Reeves <bmr@redhat.com> = 3.2-4
- [yum] call rhsm-debug with --no-subscriptions
- [powerpc] allow PowerPC plugin to run on ppc64le
- [package] add Obsoletes for sos-plugins-openstack

* Wed Oct 01 2014 Bryn M. Reeves <bmr@redhat.com> = 3.2-3
- [pam] add pam_tally2 and faillock support
- [postgresql] obtain db password from the environment
- [pcp] add Performance Co-Pilot plugin
- [nfsserver] collect /etc/exports.d
- [sosreport] handle --compression-type correctly
- [anaconda] redact passwords in kickstart configurations
- [haproxy] add new plugin
- [keepalived] add new plugin
- [lvm2] set locking_type=0 when calling lvm commands
- [tuned] add new plugin
- [cgroups] collect /etc/sysconfig/cgred
- [plugins] ensure doc text is always displayed for plugins
- [sosreport] fix the distribution version API call
- [docker] add new plugin
- [openstack_*] include broken-out openstack plugins
- [mysql] support MariaDB
- [openstack] do not collect /var/lib/nova
- [grub2] collect grub.cfg on UEFI systems
- [sosreport] handle out-of-space errors gracefully
- [firewalld] new plugin
- [networking] collect NetworkManager status
- [kpatch] new plugin
- [global] update to upstream 3.2 release

* Tue Sep 09 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-68.el6
- [ds] add collection of ds admin server configuration
  Resolves: bz994628
- [ldap] ensure /etc/openldap/ content is collected
  Resolves: bz994628
- [plugintools] preserve permissions on directories
  Resolves: bz1069786

* Thu Sep 04 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-67.el6
- [plugintools] Fix size limiting in addCopySpecLimit
  Resolves: bz1001600

* Wed Sep 03 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-66.el6
- [general] do not collect /var/log/sa
  Resolves: bz1001600

* Mon Sep 01 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-65.el6
- [grub] Fix grub.conf path for grub-1.x versions
  Resolves: bz1076388
- [ds] Fix logging exception when plugin force-enabled
  Resolves: bz994628

* Fri Aug 22 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-64.el6
- [pgsql] backport PGPASSWORD changes from upstream
  Resolves: bz1125998

* Thu Jul 31 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-63.el6
- [plugin] backport command timeout support
  Resolves: bz1005703

* Mon Jul 28 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-62.el6
- Restrict ldap and ds plugin paths to avoid collecting secrets
  Resolves: bz994628
- Add certutil output to ldap and ds plugins to summarize certs
  Resolves: bz994628

* Thu Jul 10 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-61.el6
- [powerpc] backport plugin from upstream
  Resolves: bz977190
- [devicemapper] set locking_type=0 when calling lvm2 commands
  Resolves: bz1102282
- [nfsserver] collect 'exportfs -v'
  Resolves: bz985512
- [openshift] improve password redaction
  Resolves: bz1039755
- [openshift] don't collect all of /etc/openshift
  Resolves: bz1039755

* Fri Jul 04 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-60.el6
- [mongodb] backport new plugin from upstream
- [activemq] backport new plugin from upstream
- [openshift] sync plugin with upstream
- [plugin] backport collectExtOutputs and addCopySpecs
- Make OpenShift module collect domain information
- Add 'gear' option to OpenShift module
- Add OpenShift module
  Resolves: bz1039755
- [plugin] backport addCopySpecLimit tailit parameter
  Resolves: bz1001600

* Mon Jun 30 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-58.el6
- [plugintools] preserve permissions on all path components
  Resolves: bz1069786

* Mon Jun 23 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-57.el6
- [tomcat] update for tomcat6 and add password filtering
  Resolves: bz1088070
- [filesys] collect dumpe2fs -h output by default
  Resolves: bz1105629
- [rpm] reduce number of calls to rpm
  Resolves: bz1019872
- Verify fewer packages in rpm plug-in
  Resolves: bz1019872
- [bootloader] elide bootloader password
  Resolves: bz1101311
- [plugin] backport do_path_regex_sub()
  Resolves: bz1101311
- [networking] do not attempt to read use-gss-proxy
  Resolves: bz1079954
- [mysql] limit log collection by default
  Resolves: bz1015783
- [mysql] add optional database dump support
  Resolves: bz1032262
- [docs] update man pages
  Resolves: bz1022226
- [sosreport] log exceptions during Plugin.postproc()
  Resolves: bz1020445
- [distupgrade] elide passwords in kickstart user directives
  Resolves: bz1052344

* Sat Jun 21 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-56.el6
- [ipa] add ipa-replica-manage output
  Resolves: bz1012410
- [bootloader] Include /etc/yaboot.conf
  Resolves: bz1001941
- [cluster] collect /sys/fs/gfs2/*/withdraw
  Resolves: bz997174
- [general] do not collect /var/log/sa
  Resolves: bz1001600
- [networking] avoid Cisco cdp paths in /proc and /sys
  Resolves: bz1004936
- [sar] Handle compressed binary data files better
  Resolves: bz1001600
- [sar] Add file size limits
  Resolves: bz1001600
- [sar] Enable XML data collection
  Resolves: bz1001600

* Fri Jun 20 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-55.el6
- [selinux] pass --input-logs when calling ausearch
  Resolves: bz1032706
- [printing] fix cups log file size limiting
  Resolves: bz1061529
- [auditd] fix log size limiting
  Resolves: bz1061529
- [hardware] call hardware.py directly instead of invoking python
  Resolves: bz1041770

* Thu Jun 19 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-54.el6
- [hpasm] new plugin to collect HP ASM information
  Resolves: bz915115
- [sos] improve handling of fatal IO errors
  Resolves: bz1085042
- [bootloader] collect grub.conf for UEFI based systems
  Resolves: bz1076388
- [ctdb] add plugin to collect Samba CTDB information
  Resolves: bz961041
- [keepalived] new plugin
  Resolves: bz1107862
- [sssd] scrub ldap_default_authtok in sssd plugin
  Resolves: bz1013366
- [haproxy] new plugin
  Resolves: bz1107866
- [gluster] add 'logsize' and 'all_logs' plugin options
  Resolves: bz1002619

* Tue Jun 10 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-52.el6
- Fix doRegexSub() usage in distupgrade plugin
  Resolves: bz1052344

* Mon Jun 09 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-51.el6
- Redact user home directory paths in distupgrade plugin
  Resolves: bz1052344

* Fri May 23 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-49.el6
- Add distupgrade plugin
  Resolves: bz1052344

* Thu Jan 09 2014 Bryn M. Reeves <bmr@redhat.com> = 2.2-48.el6
- Pass a --from parameter when calling crm_report
  Resolves: bz1035774

* Mon Oct 21 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-47.el6
- Fix regular expression anchors and quoting in libvirt
  Resolves: bz883811

* Fri Oct 18 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-46.el6
- Fix obfuscation of luci secrets in cluster plug-in
  Resolves: bz986301
- Fix password substitution in libvirt plug-in
  Resolves: bz883811

* Mon Oct 07 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-45.el6
- Fix collection of squid log files
  Resolves: bz955671
- Fix regex substitution in openhpi plug-in
  Resolves: bz924338
- Fix typo in /proc/kallsyms collection
  Resolves: bz970417
- Fix exception while post-processing command output
  Resolves: bz986301, bz883811

* Thu Aug 22 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-44.el6
- Add ausearch and semanage output to SELinux plug-in
  Resolves: bz876309

* Tue Aug 13 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-43.el6
- Add restricted rpm verify
  Resolves: bz888589
- Add new foreman plug-in
  Resolves: bz976386
- Collect saved vmcore-dmesg.txt files in kdump plug-in
  Resolves: bz924839
- Obfuscate luci secrets in cluster plug-in
  Resolves: bz986301
- Remove rpm list collection from RHN module
  Resolves: bz884609
- Add gluster geo-replication status and sync with RHS version
  Resolves: bz868711
- Obscure passwords in libvirt and corosync data
  Resolves: bz883811
- Make krb5 plug-in conform with sos-2.2 plug-in API
  Resolves: bz987103
- Add further NIS data collection
  Resolves: bz928748
- Fix symbol collection for modern kernels
  Resolves: bz970417
- Disable 'ipsec barf' collection in openswan plug-in
  Resolves: bz924925
- Add pam_ldap.conf collection to ldap plug-in
  Resolves: bz877395
- Force LC_ALL=C for external commands
  Resolves: bz888488
- Rationalise lvm2 plug-in lvmdump options
  Resolves: bz980959
- Backport addCopySpecs from upstream
  Resolves: bz924338, bz907861

* Mon Aug 12 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-42.el6
- Update sosreport user interface text
  Resolves: bz878589
- Preserve ownership and permissions on collected files
  Resolves: bz888724
- Do not collect krb5.keytab in samba plug-in
  Resolves: bz987103
- Collect output of 'ls -l /var/named' in named plug-in
  Resolves: bz896713
- Collect /var/log/squid in squid plug-in
  Resolves: bz955671
- Fix systool invocation in device-mapper plug-in
  Resolves: bz868719
- Add plug-in to collect OpenHPI configuration
  Resolves: bz924338
- Fix traceback in sar module when /var/log/sa does not exist
  Resolves: bz883443
- Collect mountstats and mountinfo files in filesys plug-in
  Resolves: bz988417
- Add crm_report integration for pacemaker to cluster plug-in
  Resolves: bz989292

* Tue Jul 30 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-41.el6
- Exclude RPC files from procfs data collection in networking module
  Resolves: bz913201
- Add NFS client plug-in
  Resolves: bz907861
- Restrict wbinfo collection to local domain in samba plug-in
  Resolves: bz986973

* Tue Jul 16 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-40.el6
- Backport SELinux enhancements from upstream
  Resolves: bz876309
- Fix invocation of 'udevadm info' in device-mapper plug-in
  Resolves: bz947424

* Thu May 23 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-39.el6
- Always invoke tar with '-f-' option
  Resolves: bz966602

* Mon Jan 21 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-38.el6
- Fix interactive mode regression when --ticket unspecified
  Resolves: bz822113

* Fri Jan 18 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-37.el6
- Fix propagation of --ticket parameter in interactive mode
  Resolves: bz822113

* Thu Jan 17 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-36.el6
- Revert OpenStack patch
  Resolves: bz840057

* Wed Jan  9 2013 Bryn M. Reeves <bmr@redhat.com> = 2.2-35.el6
- Report --name and --ticket values as defaults
  Resolves: bz822113
- Fix device-mapper command execution logging
  Resolves: bz824378
- Fix data collection and rename PostreSQL module to pgsql
  Resolves: bz852049

* Fri Oct 19 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-34.el6
- Add support for content delivery hosts to RHUI module
  Resolves: bz821323

* Thu Oct 18 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-33.el6
- Add Red Hat Update Infrastructure module
  Resolves: bz821323
- Collect /proc/iomem in hardware module
  Resolves: bz840975
- Collect subscription-manager output in general module
  Resolves: bz825968
- Collect rhsm log files in general module
  Resolves: bz826312
- Fix exception in gluster module on non-gluster systems
  Resolves: bz849546
- Fix exception in psql module when dbname is not given
  Resolves: bz852049

* Wed Oct 17 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-32.el6
- Collect /proc/pagetypeinfo in memory module
  Resolves: bz809727
- Strip trailing newline from command output
  Resolves: bz850433
- Add sanlock module
  Resolves: bz850779
- Do not collect archived accounting files in psacct module
  Resolves: bz850542
- Call spacewalk-debug from rhn module to collect satellite data
  Resolves: bz859142

* Mon Oct 15 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-31.el6
- Avoid calling volume status when collecting gluster statedumps
  Resolves: bz849546
- Use a default report name if --name is empty
  Resolves: bz822113
- Quote tilde characters passed to shell in RPM module
  Resolves: bz821005
- Collect KDC and named configuration in ipa module
  Resolves: bz825149
- Sanitize hostname characters before using as report path
  Resolves: bz822174
- Collect /etc/multipath in device-mapper module
  Resolves: bz817093
- New plug-in for PostgreSQL
  Resolves: bz852049
- Add OpenStack module
  Resolves: bz840057
- Avoid deprecated sysctls in /proc/sys/net
  Resolves: bz834594
- Fix error logging when calling external programs
  Resolves: bz824378
- Use ip instead of ifconfig to generate network interface lists
  Resolves: bz833170

* Wed May 23 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-29.el6
- Collect the swift configuration directory in gluster module
  Resolves: bz822442
- Update IPA module and related plug-ins
  Resolves: bz812395

* Fri May 18 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-28.el6
- Collect mcelog files in the hardware module
  Resolves: bz810702

* Wed May 02 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-27.el6
- Add nfs statedump collection to gluster module
  Resolves: bz752549

* Tue May 01 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-26.el6
- Use wildcard to match possible libvirt log paths
  Resolves: bz814474

* Mon Apr 23 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-25.el6
- Add forbidden paths for new location of gluster private keys
  Resolves: bz752549

* Fri Mar  9 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-24.el6
- Fix katello and aeolus command string syntax
  Resolves: bz752666
- Remove stray hunk from gluster module patch
  Resolves: bz784061

* Thu Mar  8 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-22.el6
- Correct aeolus debug invocation in CloudForms module
  Resolves: bz752666
- Update gluster module for gluster-3.3
  Resolves: bz784061
- Add additional command output to gluster module
  Resolves: bz768641
- Add support for collecting gluster configuration and logs
  Resolves: bz752549

* Wed Mar  7 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-19.el6
- Collect additional diagnostic information for realtime systems
  Resolves: bz789096
- Improve sanitization of RHN user and case number in report name
  Resolves: bz771393
- Fix verbose output and debug logging
  Resolves: bz782339
- Add basic support for CloudForms data collection
  Resolves: bz752666
- Add support for Subscription Asset Manager diagnostics
  Resolves: bz752670

* Tue Mar  6 2012 Bryn M. Reeves <bmr@redhat.com> = 2.2-18.el6
- Collect fence_virt.conf in cluster module
  Resolves: bz760995
- Fix collection of /proc/net directory tree
  Resolves: bz730641
- Gather output of cpufreq-info when present
  Resolves: bz760424
- Fix brctl showstp output when bridges contain multiple interfaces
  Resolves: bz751273
- Add /etc/modprobe.d to kernel module
  Resolves: bz749919
- Ensure relative symlink targets are correctly handled when copying
  Resolves: bz782589
- Fix satellite and proxy package detection in rhn plugin
  Resolves: bz749262
- Collect stderr output from external commands
  Resolves: bz739080
- Collect /proc/cgroups in the cgroups module
  Resolve: bz784874
- Collect /proc/irq in the kernel module
  Resolves: bz784862
- Fix installed-rpms formatting for long package names
  Resolves: bz767827
- Add symbolic links for truncated log files
  Resolves: bz766583
- Collect non-standard syslog and rsyslog log files
  Resolves: bz771501
- Use correct paths for tomcat6 in RHN module
  Resolves: bz749279
- Obscure root password if present in anacond-ks.cfg
  Resolves: bz790402
- Do not accept embedded forward slashes in RHN usernames
  Resolves: bz771393
- Add new sunrpc module to collect rpcinfo for gluster systems
  Resolves: bz784061

* Tue Nov  1 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-17
- Do not collect subscription manager keys in general plugin
  Resolves: bz750607

* Fri Sep 23 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-16
- Fix execution of RHN hardware.py from hardware plugin
  Resolves: bz736718
- Fix hardware plugin to support new lsusb path
  Resolves: bz691477

* Fri Sep 09 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-15
- Fix brctl collection when a bridge contains no interfaces
  Resolves: bz697899
- Fix up2dateclient path in hardware plugin
  Resolves: bz736718

* Mon Aug 15 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-14
- Collect brctl show and showstp output
  Resolves: bz697899
- Collect nslcd.conf in ldap plugin
  Resolves: bz682124

* Sun Aug 14 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-11
- Truncate files that exceed specified size limit
  Resolves: bz683219
- Add support for collecting Red Hat Subscrition Manager configuration
  Resolves: bz714293
- Collect /etc/init on systems using upstart
  Resolves: bz694813
- Don't strip whitespace from output of external programs
  Resolves: bz713449
- Collect ipv6 neighbour table in network module
  Resolves: bz721163
- Collect basic cgroups configuration data
  Resolves: bz729455

* Sat Aug 13 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-10
- Fix collection of data from LVM2 reporting tools in devicemapper plugin
  Resolves: bz704383
- Add /proc/vmmemctl collection to vmware plugin
  Resolves: bz709491

* Fri Aug 12 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-9
- Collect yum repository list by default
  Resolves: bz600813
- Add basic Infiniband plugin
  Resolves: bz673244
- Add plugin for scsi-target-utils iSCSI target
  Resolves: bz677124
- Fix autofs plugin LC_ALL usage
  Resolves: bz683404
- Fix collection of lsusb and add collection of -t and -v outputs
  Resolves: bz691477
- Extend data collection by qpidd plugin
  Resolves: bz726360
- Add ethtool pause, coalesce and ring (-a, -c, -g) options to network plugin
  Resolves: bz726427

* Thu Apr 07 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-8
- Use sha256 for report digest when operating in FIPS mode
  Resolves: bz689387

* Tue Apr 05 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-7
- Fix parted and dumpe2fs output on s390
  Resolves: bz622784

* Fri Feb 25 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-6
- Fix collection of chkconfig output in startup.py
  Resolves: bz659467
- Collect /etc/dhcp in dhcp.py plugin
  Resolves: bz676522
- Collect dmsetup ls --tree output in devicemapper.py
  Resolves: bz675559
- Collect lsblk output in filesys.py
  Resolves: bz679433

* Thu Feb 24 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-4
- Fix collection of logs and config files in sssd.py
  Resolves: bz624162
- Add support for collecting entitlement certificates in rhn.py
  Resolves: bz678665

* Thu Feb 03 2011 Bryn M. Reeves <bmr@redhat.com> = 2.2-3
- Fix cluster plugin dlm lockdump for el6
  Resolves: bz622407
- Add sssd plugin to collect configuration and logs
  Resolves: bz624162
- Collect /etc/anacrontab in system plugin
  Resolves: bz622527
- Correct handling of redhat-release for el6
  Resolves: bz622528

* Thu Jul 29 2010 Adam Stokes <ajs at redhat dot com> = 2.2-2
- Resolves: bz582259
- Resolves: bz585942
- Resolves: bz584253
- Resolves: bz581817

* Thu Jun 10 2010 Adam Stokes <ajs at redhat dot com> = 2.2-0
- Resolves: bz581921
- Resolves: bz584253
- Resolves: bz562651
- Resolves: bz566170
- Resolves: bz586450
- Resolves: bz588223
- Resolves: bz559737
- Resolves: bz586405
- Resolves: bz598978
- Resolves: bz584763

* Wed Apr 28 2010 Adam Stokes <ajs at redhat dot com> = 2.1-0
- Resolves: bz585923
- Resolves: bz585942
- Resolves: bz586409
- Resolves: bz586389
- Resolves: bz548096
- Resolves: bz557828
- Resolves: bz563637
- Resolves: bz584253
- Resolves: bz462823
- Resolves: bz528881
- Resolves: bz566170
- Resolves: bz578787
- Resolves: bz581817
- Resolves: bz581826
- Resolves: bz584695
- Resolves: bz568637
- Resolves: bz584767
- Resolves: bz586370

* Mon Apr 12 2010 Adam Stokes <ajs at redhat dot com> = 2.0-0
- Resolves: bz580015

* Tue Mar 30 2010 Adam Stokes <ajs at redhat dot com> = 1.9-3
- fix setup.py to autocompile translations and man pages
- rebase 1.9

* Fri Mar 19 2010 Adam Stokes <ajs at redhat dot com> = 1.9-2
- updated translations

* Thu Mar 04 2010 Adam Stokes <ajs at redhat dot com> = 1.9-1
- version bump 1.9
- replaced compression utility with xz
- strip threading/multiprocessing
- simplified progress indicator
- pylint update
- put global vars in class container
- unittests
- simple profiling
- make use of xgettext as pygettext is deprecated

* Mon Jan 18 2010 Adam Stokes <ajs at redhat dot com> = 1.8-21
- more sanitizing options for log files
- rhbz fixes from RHEL version merged into trunk
- progressbar update
