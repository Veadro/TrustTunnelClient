#!/bin/bash -x

increment_version() {
  major=${1%%.*}
  minor=$(echo ${1#*.} | sed -e "s/\.[0-9]*//")
  revision=${1##*.}
  echo ${major}.${minor}.$((revision+1))
}

version_name=$(cat common/include/vpn/version.h | grep "define" | sed -e "s/^.*VERSION \"//g" | sed -e "s/\"$//g")
echo "Version before increment is ${version_name}"
new_version_name=${1:-$(increment_version ${version_name})}
echo "New version name is ${new_version_name}"

version_name=$(echo ${version_name} | sed -e 's/\./\\\./g')

old_part="VERSION \"${version_name}"
new_part="VERSION \"${new_version_name}"
sed -i -e "s/${old_part}/${new_part}/" common/include/vpn/version.h

sed -i -e '3{s/##/##/;t;s/^/## '${new_version_name}'\n\n/}' CHANGELOG.md
