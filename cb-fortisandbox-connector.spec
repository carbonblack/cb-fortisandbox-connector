# -*- mode: python -*-
from PyInstaller.utils.hooks import get_package_paths
datas = [(get_package_paths('cbint')[1], 'cbint')]
datas.extend([(get_package_paths('sqlite3')[1], 'sqlite3')])
datas.extend([ (HOMEPATH + '/cbapi/response/models/*', 'cbapi/response/models/'),
                     (HOMEPATH + '/cbapi/protection/models/*', 'cbapi/protection/models/'),
                     (HOMEPATH + '/cbapi/psc/defense/models/*', 'cbapi/psc/defense/models/')])
a = Analysis(['scripts/cb-fortisandbox-connector'],
             pathex=['.'],
             hiddenimports=['sqlite3', 'cbint','cbint.utils.cbserver', 'cbint.utils.bridge', 'unicodedata'],
             datas=datas,
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='cb-fortisandbox-connector',
          debug=False,
          strip=None,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='cb-fortisandbox-connector')
