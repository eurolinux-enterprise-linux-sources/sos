package = sos
version = $(shell grep Version sos.spec | awk '{print $$2}')
package_version = $(package)-$(version)
package_version_tar = $(version).tar.gz

sources:
	cp -a src $(package_version) \
	&& tar czvvf $(package_version_tar) $(package_version)/ \
 	&& rm -rf $(package_version)

