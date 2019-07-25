package secureoverlay2 // import "github.com/docker/docker/daemon/graphdriver/secureoverlay2"

import "github.com/docker/docker/daemon/graphdriver/copy"

func dirCopy(srcDir, dstDir string) error {
	return copy.DirCopy(srcDir, dstDir, copy.Content, false)
}
