%global gem_name puppet-lint-cnvr-plugins

Name: rubygem-%{gem_name}
Version: 1.0.0
Summary: A utility for inspecting x509 certificates
Release: 1%{?dist}
License: CNVR
Group: Applications/System
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
BuildRequires: rubygems-devel

%description
A utility for inspecting x509 certificates
Git: %{git_sha1} (%{git_describe})

%prep
%setup -q

%build
gem build %{gem_name}.gemspec
%gem_install

%install
# Installing ruby source
mkdir -p %{buildroot}%{gem_dir}
cp -a ./%{gem_dir}/* %{buildroot}%{gem_dir}/
echo -e "%{gem_cache}\n%{gem_instdir}\n%{gem_spec}\n%doc %{gem_docdir}" >> files.list

# Installing included commands
if [ -d ./%{_bindir} ]; then
  mkdir -p %{buildroot}%{_bindir}
  cp -a ./%{_bindir}/* %{buildroot}%{_bindir}
  echo "%{_bindir}/*" >> files.list
fi

# Installing compiled code
if [ -d .%{gem_extdir_mri} ]; then
  mkdir -p %{buildroot}%{gem_extdir_mri}
  cp -a .%{gem_extdir_mri}/{gem.build_complete,*.so} %{buildroot}%{gem_extdir_mri}/
  echo "%{gem_extdir_mri}" >> files.list
fi

%files -f files.list
