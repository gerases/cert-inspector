%global gem_name cnvr-cert-inspector

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
gem install -V --local --install-dir .%{gem_dir} --bindir .%{_bindir} \
  --force --no-document --no-user-install %{gem_name}-%{version}.gem

%install
mkdir -p %{buildroot}%{gem_dir}
cp -a ./%{gem_dir}/* %{buildroot}%{gem_dir}/
echo -e "%{gem_cache}\n%{gem_instdir}\n%{gem_spec}" >> files.list

if [ -d ./%{_bindir} ]; then
  mkdir -p %{buildroot}%{_bindir}
  cp -a ./%{_bindir}/* %{buildroot}%{_bindir}
  echo "%{_bindir}/*" >> files.list
fi

if [ -d .%{gem_extdir_mri} ]; then
  mkdir -p %{buildroot}%{gem_extdir_mri}
  cp -a .%{gem_extdir_mri}/{gem.build_complete,*.so} %{buildroot}%{gem_extdir_mri}/
  echo "%{gem_extdir_mri}" >> files.list
fi

%check
export GEM_PATH=$(pwd)/gems/ruby/3.1.0${GEM_PATH:+:$GEM_PATH}
export PATH=$(pwd)/gems/ruby/3.1.0/bin:$PATH
rspec spec

%files -f files.list
