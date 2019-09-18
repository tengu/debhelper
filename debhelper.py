#!/usr/bin/env python3
"""make apt repo easy.
"""
import sys,os
from subprocess import Popen, PIPE, call
import getpass
import glob
import json
import pwd
import re
import socket
import tempfile

import baker


default_conf_file = './debhelper.json'


defaults = {
    'user': 'debrepo', 
    'uid': 1900,
    'repo_path': '/var/data/debrepo/',
    # This command expects passphrase from stdin. cwd must be the repo dir.
    'gpg_sign_cmd': '/usr/bin/gpg -as --pinentry-mode loopback --yes --passphrase-fd 0 -u {keyname} -o Release.gpg Release',
    'gpg_passphrase': 'hirakegoma',
    'verbose': 0,
}


def config(conf_file=None, **override):
    """load config file if any.
    """
    if not conf_file:
        conf_file = default_conf_file
    config = defaults.copy()
    with open(conf_file, 'r') as config_json:
        config.update(
            json.load(config_json)
        )
    config.update(override)
    return config


class DebRepo:
    """
    Commands for easy deb repo management.
    """
    def __init__(
            self,
            user, 
            uid,
            repo_path,
            gpg_sign_cmd,
            gpg_passphrase,
            verbose=None,
            dryrun=False,
    ):
        self.user = user
        self.uid = uid
        self.gid = None
        self.repo_path = repo_path
        self.gpg_sign_cmd = gpg_sign_cmd
        self.gpg_passphrase = gpg_passphrase
        self.keyname_file = os.path.join(self.repo_path, 'keyname')
        self.verbose = verbose
        self.dryrun = dryrun
        if self.dryrun:
            self.verbose = 2    # dryrun overrides verbose

    def show(self, *args, prefix=None):
        """Print command to be executed.
        """
        if prefix is None:
            prefix = '$'
        if self.verbose >= 2:
            print(prefix, *args)

    def report(self, *msg, prefix=None):
        """Print what just happened. 
        """
        if prefix is not None:
            pass
        elif self.verbose >= 2:
            prefix = '#'
        if prefix:
            msg = (prefix,) + msg
        if self.verbose >= 1:
            print(*msg)

    # xxx should be called get_or_create_user
    def get_user_attributes(self):
        """Resolve uid and gid of the user.
        """
        try:
            pwd_entry=pwd.getpwnam(self.user)
        except KeyError:
            pwd_entry=None

        if pwd_entry:
            self.report('user exists:', pwd_entry.pw_name, pwd_entry.pw_uid)
        else:
            s = call(
                [
                    '/usr/bin/sudo',
                    '/usr/sbin/useradd',
                    '--create-home',
                    '--uid',
                    str(self.uid),
                    '--shell',
                    '/bin/bash',
                    self.user
                ]
            )
            assert s == 0, ('failed to create user',)
            pwd_entry=pwd.getpwnam(self.user)
            self.report('created user', pwd_entry.pw_name, pwd_entry.pw_uid)
        assert pwd_entry

        self.uid = pwd_entry.pw_uid
        self.gid=pwd_entry.pw_gid


    def as_user(self, cmd):
        """Run the command as the user, subject to `verbose` and `dryrun`.
        Returns (returncode, stdout, stderr).
        """
        self.show(cmd, prefix=f'{self.user}$', )
        if self.dryrun:
            return None, b'', b''
        return self._as_user(cmd)


    def _as_user(self, cmd):
        """Unconditionally run the command as the user and return (returncode, stdout, stderr)
        """
        p = Popen(['/usr/bin/sudo', '/bin/su', '--login', '--command', '/bin/bash', self.user], 
                stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate(cmd.encode('utf8'))
        return p.returncode, out, err
    

    def extract_key_name(self):
        """Extract gpg keyname that was registered for debrepo.
        """
        # quick and dirty regex parsing..
        # consider using gnupg.
        _, out, _ = self.as_user('/usr/bin/gpg --list-keys')
        patterns = [
            'pub\s+.*?uid\s+debrepo.*?sub\s+\w+/(\w+)\s+[\w-]+$',
            '^pub.*?\n\s+(.*?)\nuid',
        ]
        keyname = None
        out_str = out.decode('utf8')
        for pattern in patterns:
            m=re.search(pattern, out_str, flags=re.M|re.DOTALL)
            if m:
                keyname=m.group(1)
                break
        return keyname


    def generate_key(self):
        """Generate gpg key for debrepo purpose.
        gpg --batch --gen-key /tmp/gen-key.cfg
        """
        cmd = self.generate_key_cmd()
        self.show(cmd)
        if self.dryrun:
            return None
        s, _, _ = self.as_user(cmd)
        assert s == 0, ('failed to generate key', cmd)
        keyname = self.extract_key_name()
        return keyname


    def generate_key_cmd(self, cfg_path=None):
        """Command for generating gpg key.
        Valid config must exist at cfg_path for invocation to succeed.
        """
        # TODO: use tempfile
        if cfg_path is None:
            cfg_path = '/tmp/gen-key.cfg'
        self.create_gen_key_cfg_file(cfg_path)
        return '/usr/bin/gpg --batch --gen-key {cfg_path}'.format(cfg_path=cfg_path)


    def create_gen_key_cfg_file(self, cfg_path):
        """Create config file for gpg key generation.
        """
        gen_key_cfg=f"""
        Key-Type: 1
        Key-Length: 2048
        Subkey-Type: 1
        Subkey-Length: 2048
        Name-Real: {self.user}
        Name-Email: {self.user}@example.com
        Passphrase: {self.gpg_passphrase}
        Expire-Date: 0
        """
        with open(cfg_path, 'w') as cfg_file:
            cfg_file.write(gen_key_cfg)


    def save_keyname_file(self, keyname):
        """Place the keyname in a well-known file ($repo/keyname) so that signer can look it up.
        Does something like:
        gpg --list-keys | grep -A2 debrepo | grep ^sub | tr '/' ' ' | awk '{ print $3 }' > keyname
        """
        if self.dryrun:
            keyname = '{keyname}'
        else:
            assert keyname, ('need keyname', keyname)

        cmd=f'/bin/echo "{keyname}" > {self.keyname_file}'
        s, out, err = self.as_user(cmd)

        if s == 0:
            self.report(f'Wrote {self.keyname_file}')
        elif s == None:
            pass                # dryrun
        else:
            self.report(f'Failed to save {self.keyname_file}')
            self.report('\t', err.decode('utf8'))
        return s


    def save_pubkey_file(self, keyname):
        """Create pubkey file.
        Does something like:
        gpg -a --export {keyname} > pubkey
        """
        if self.dryrun:
            keyname = '{keyname}'
        else:
            assert keyname, 'need keyname'

        pubkey_file=os.path.join(self.repo_path, 'pubkey')
        s, out, err = self.as_user(f'/usr/bin/gpg -a --export {keyname} > {pubkey_file}')

        if s == 0:
            self.report(f'wrote {pubkey_file}')
        elif s is None:         # dryrun
            pass
        else:
            self.report(f'failed to save pukey file {pubkey_file}')
            self.report(err)
        return s


    def create_repo_dir(self):
        """Create the repo dir with right permissions.
        """
        if os.path.exists(self.repo_path):
            self.report(f'repo dir exists: {self.repo_path}')
            status = 0
        else:
            cmd=['/usr/bin/sudo',
                 '/usr/bin/install', '-d',
                 '-m', '02775', 
                 '-o', self.user, 
                 '-g', str(self.gid),
                 self.repo_path]
            status = self._call(cmd)
            if status == 0:
                self.report(f'created repo dir: {self.repo_path}')
            elif status is None:
                pass
            else:
                self.report(f'failed to create repo dir: {self.repo_path}')
        return status


    def get_or_create_key_name(self, gen_key=True):
        """Get the gpg keyname for debrepo, generating a key if necessary.
        """
        keyname = self.extract_key_name()
        if keyname:
            self.report(f'found keyname: {keyname}')
        elif gen_key:
            keyname = self.generate_key()
            self.report(f'generated key: {keyname}')
        else:
            print(f'gpg key for debrepo was not found for user {self.user}. '
                  'please use $0 generate_key, then try this command again')
            self.report('no keyname')
            keyname = None
        return keyname

                 
    def setup_repo(self, gen_key=True):
        """Setup a simple, signed apt repository.
        """
        self.get_user_attributes()
        keyname = self.get_or_create_key_name(gen_key=gen_key)
        if not keyname and not self.dryrun: 
            return 1
        # xxx these should throw exception for status>1.
        self.create_repo_dir()
        self.save_keyname_file(keyname)
        self.save_pubkey_file(keyname)
        return 0


    def ensure_correct_user(self):
        """Die with a message unless the current user is the right one.
        """
        username = getpass.getuser()
        # xxx thow a suitable exception.
        assert username == 'debrepo', ('this command must be run as user `debrepo`, not', username)


    def read_keyname(self):
        """Read the keyname from the well-known file.
        """
        self.show(f'cat {self.keyname_file}')
        with open(self.keyname_file) as f:
            keyname = f.readline().strip()
        self.report('Using key:', keyname)
        return keyname


    def update_repo(self, sign=True, verbose=False):
        """update the repo index to incoporate newly added deb files.
            apt-ftparchive packages . > Packages
            gzip -c Packages > Packages.gz
            apt-ftparchive release . > Release
            gpg --yes -abs -u $(KEY) -o Release.gpg Release

        note: must be run as "debrepo" user who has the gpg key.
        """
        self.ensure_correct_user()

        keyname=self.read_keyname()
        self.show(f'cd {self.repo_path}')
        os.chdir(self.repo_path)
        cmds=[
            'apt-ftparchive packages . > Packages',
            'gzip -c Packages > Packages.gz',
            'apt-ftparchive release . > Release',
        ]
        for cmd in cmds:
            self.show(cmd)
            s=call(cmd, shell=True)
            if s!=0:
                print >>sys.stderr, 'error:', cmd
                return 1
        self.report('Updated Packages and Release.')
        if sign:
            s = self.sign_release(keyname)
        self.report('Updated repo:', self.repo_path)
        return s


    def sign_release(self, keyname):
        """
        Sign the $REPO_PATH/Release file to create Release.gpg.
        Must be call in $REPO_PATH.
        """
        s = call_and_feed(
            self.gpg_sign_cmd.format(keyname=keyname),
            self.gpg_passphrase.encode('utf8')
        )
        self.report('Signed Release.')
        return s
        
    def _call(self, cmd):
        """invoke command conditionally
        """
        # xx interpolating exec tuple into a string might produce a
        # malformed command; some terms might have to be quoted..
        self.show(*cmd)
        if self.dryrun:
            return None
        return call(cmd)


@baker.command
def setup_repo(conf_file=None, verbose=1, dryrun=False, gen_key=True):
    """Setup a simple, signed apt repository.

    Create debrepo user.
    Create gpg key for signing the repo.
    Create the repo directory.
    Create the public key for client to import.
    """
    dr = DebRepo(dryrun=dryrun, **config(conf_file=conf_file, verbose=verbose))
    s = dr.setup_repo(gen_key=gen_key)
    sys.exit(s)


@baker.command
def update_repo(conf_file=None, verbose=1, dryrun=False):
    """Update the repo so that the newly added deb files are incorporated.

    It does the equivalent of:
    cd /var/data/debrepo/
    apt-ftparchive packages . > Packages
    gzip -c Packages > Packages.gz
    apt-ftparchive release . > Release
    gpg --yes -abs -u `cat keyname` -o Release.gpg Release
    """
    dr = DebRepo(dryrun=dryrun, **config(conf_file=conf_file, verbose=verbose))
    s = dr.update_repo()
    sys.exit(s)


@baker.command
def util_dump_config(conf_file=None, verbose=1, dryrun=False, **override):
    """Dump the configuration as json.
    """
    # xx this does not account for the effect of dryrun.
    print(json.dumps(config(conf_file=conf_file, verbose=verbose)))


@baker.command
def util_generate_key(conf_file=None):
    """Generate the gpg key for debrepo. Part of setup_repo.
    """
    keyname = DebRepo(**config(conf_file=conf_file)).generate_key()
    print(keyname)


@baker.command
def util_sign_release():
    """Sign the Relase file. Part of update_repo.
    """
    os.chdir(REPO_PATH)
    dr = DebRepo()
    keyname = dr.read_keyname()
    out, err = dr.sign_release(keyname)
    print(out)
    print(err)


@baker.command
def util_read_keyname(conf_file=None, verbose=0, dryrun=False):
    """Read the gpg keyname. For troubleshooting.
    """
    dr = DebRepo(dryrun=dryrun, **config(conf_file=conf_file, verbose=verbose))
    keyname = dr.read_keyname()
    print(keyname)


@baker.command
def util_entropy():
    """Unblock gpg by providing randomness to the kernel.

    Sometimes gpg blocks waiting for kernel to gain some randomness.
    If setup_repo or update_repo blocks, run this command.
    """
    call('/usr/bin/sudo /usr/sbin/rngd -f -r /dev/urandom', shell=True)


#### Remote repo update client-server protocol. Not Ready for primetime yet.
# @baker.command
def push(repo_host, user='debrepo', verbose=False):
    """make deb files avaiable via the repo.
    push deb files fed to stdin to the repo.

    stdin:  deb file paths

    usage:  
            find build -name '*.deb' | aptrepo.py push repo-host

    to make the deb files immediately available to the local host, follow with:

            aptrepo.py apt_get_update_selectively repo-host.list

    prerequisite: 
     * This command must be installed on the repo_host and be available in the path of the repo user.
       Test with:
            ssh debrepo@repo-host aptrepo.py 
       Help menu should be printed.
    """
    # input stream: deb file paths
    # convert this to cpio stream
    cpio=Popen(['/bin/cpio', '-o'], stdout=PIPE)

    # push to the other end
    user_host='{user}@{repo_host}'.format(user=user, repo_host=repo_host)
    cmd=['/usr/bin/ssh', user_host, 'aptrepo.py', 'receive']
    if verbose:
        print(' '.join(cmd))

    push=Popen(cmd, stdin=cpio.stdout)

    sys.exit(push.wait())


# @baker.command
def receive(repo_path='/var/data/debrepo/', verbose=True):
    """handler or server for push.
    receive cpio stream from stdin.
    place received files under the repo.
    update index.

    must be run as the repo_user with the gpg key pair.
    """

    workdir=tempfile.mkdtemp(prefix='aptrepo-incoming-')
    os.chdir(workdir)
    cpio=Popen(['/bin/cpio', '-id', '--no-absolute-filenames'
                , '--verbose'
                , '--quiet'
            ], stdout=PIPE, stderr=PIPE)
    out,err=cpio.communicate()

    deb_files=filter(None, err.split('\n'))
    if verbose:
        print >>sys.stderr, 'workdir:', workdir

    for deb_file in deb_files:
        if os.path.exists(deb_file):
            # it's path from --verbose
            dest=os.path.join(repo_path, os.path.basename(deb_file))
            os.rename(deb_file, dest)
            if verbose:
                print >>sys.stderr, deb_file, '-->', dest
        else:
            # not a path, but an error message
            print >>sys.stderr, 'err:', deb_file

    # todo: clean up workdir
    update_repo(repo=repo_path, verbose=verbose)


#### util


def call_and_feed(cmd, data):
    """
    call `cmd` and feed `data` to stdin.
    """
    p = Popen(cmd, shell=True, stdin=PIPE)
    p.stdin.write(data)
    p.stdin.close()
    return p.wait()


if __name__=='__main__':

    baker.run()
