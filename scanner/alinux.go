package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type alinux struct {
	redhatBase
}

// newAlinux is constructor
func newAlinux(c config.ServerInfo) *alinux {
	r := &alinux{
		redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
			sudo: rootPrivAlinux{},
		},
	}
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

func (o *alinux) checkScanMode() error { return nil }

func (o *alinux) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	return o.execCheckDeps(o.depsDeep())
}

func (o *alinux) depsFast() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}
	return []string{"yum-utils"}
}

func (o *alinux) depsFastRoot() []string {
	if o.getServerInfo().Mode.IsOffline() {
		return []string{}
	}
	return []string{"yum-utils"}
}

func (o *alinux) depsDeep() []string { return o.depsFastRoot() }

func (o *alinux) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *alinux) sudoNoPasswdCmdsFast() []cmd { return []cmd{} }

func (o *alinux) sudoNoPasswdCmdsFastRoot() []cmd {
	if !o.ServerInfo.IsContainer() {
		return []cmd{
			{"repoquery -h", exitStatusZero},
			{"needs-restarting", exitStatusZero},
			{"which which", exitStatusZero},
			{"stat /proc/1/exe", exitStatusZero},
			{"ls -l /proc/1/exe", exitStatusZero},
			{"cat /proc/1/maps", exitStatusZero},
			{"lsof -i -P -n", exitStatusZero},
		}
	}
	return []cmd{
		{"repoquery -h", exitStatusZero},
		{"needs-restarting", exitStatusZero},
	}
}

func (o *alinux) sudoNoPasswdCmdsDeep() []cmd { return o.sudoNoPasswdCmdsFastRoot() }

type rootPrivAlinux struct{}

func (o rootPrivAlinux) repoquery() bool    { return false }
func (o rootPrivAlinux) yumMakeCache() bool { return false }
func (o rootPrivAlinux) yumPS() bool        { return false }
