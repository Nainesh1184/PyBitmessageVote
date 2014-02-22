#! /usr/bin/env python

import sys
import os
import errno
import tempfile
import shared
from multiprocessing import Process


class singleinstance:
    """
    Implements a single instance application by creating a lock file based on the full path to the script file.

    This is based upon the singleton class from tendo https://github.com/pycontribs/tendo
    which is under the Python Software Foundation License version 2    
    """
    def __init__(self, flavor_id=""):
        import sys
        self.initialized = False
        basename = os.path.splitext(os.path.abspath(sys.argv[0]))[0].replace("/", "-").replace(":", "").replace("\\", "-") + '-%s' % flavor_id + '.lock'
        if shared.allowMultipleInstances:
            shared.instanceNo = 0
            while True:
                shared.instanceNo += 1
                self.lockfile = os.path.normpath(tempfile.gettempdir() + '/' + basename + "-instance-%d" % shared.instanceNo )
                if self.tryLockFile( self.lockfile ):
                    break
            
        else:
            self.lockfile = os.path.normpath(tempfile.gettempdir() + '/' + basename)
            if not self.tryLockFile( self.lockfile ):
                print 'Another instance of this application is already running'
                sys.exit(-1)

        print "Lockfile: %s" % ( self.lockfile )
        self.initialized = True
        
    def tryLockFile(self, filename):
        if sys.platform == 'win32':
            try:
                # file already exists, we try to remove (in case previous execution was interrupted)
                if os.path.exists(filename):
                    os.unlink(filename)
                self.fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            except OSError:
                type, e, tb = sys.exc_info()
                if e.errno == 13:
                    return False
                print(e.errno)
                raise
        else:  # non Windows
            import fcntl  # @UnresolvedImport
            self.fp = open(filename, 'w')
            try:
                fcntl.lockf(self.fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                return False
            
        return True

    def __del__(self):
        import sys
        if not self.initialized:
            return
        try:
            if sys.platform == 'win32':
                if hasattr(self, 'fd'):
                    os.close(self.fd)
                    os.unlink(self.lockfile)
            else:
                import fcntl  # @UnresolvedImport
                fcntl.lockf(self.fp, fcntl.LOCK_UN)
                if os.path.isfile(self.lockfile):
                    os.unlink(self.lockfile)
        except Exception, e:
            sys.exit(-1)
