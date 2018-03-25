import errno
import os
import shutil
import sys

from pkg_resources import resource_filename
from setuptools import setup, find_packages

def install_configs():
    """Install configuration files to /etc/"""
    dst_faucet_conf_dir = '/etc/faucet/'
    dst_gasket_conf_dir = '/etc/faucet/gasket/'

    src_faucet_conf_dir = resource_filename(__name__, 'etc/faucet')
    src_gasket_conf_dir = resource_filename(__name__, 'etc/faucet/gasket')
    gasket_log_dir = '/var/log/faucet/gasket/'

    try:
        if not os.path.exists(dst_faucet_conf_dir):
            print ("Creating %s" % dst_faucet_conf_dir)
            os.makedirs(dst_faucet_conf_dir)
        if not os.path.exists(dst_gasket_conf_dir):
            print ("Creating %s" % dst_gasket_conf_dir)
            os.makedirs(dst_gasket_conf_dir)
        for src_dir, dst_dir in [(src_faucet_conf_dir, dst_faucet_conf_dir), (src_gasket_conf_dir, dst_gasket_conf_dir)]:
            for filename in os.listdir(src_dir):
                src_file = os.path.join(src_dir, filename)
                dst_file = os.path.join(dst_dir, filename)
                if os.path.isfile(src_file) and not os.path.isfile(dst_file):
                    print('Copying %s to %s' % (src_file, dst_file))
                    shutil.copy(src_file, dst_file)
        if not os.path.exists(gasket_log_dir):
            print("Creating %s" % gasket_log_dir)
            os.makedirs(gasket_log_dir)
    except OSError as ex:
        if ex.errno == errno.EACCES:
            print('Permission denied creating %s, skipping ocpying configs' % ex.filename)
        else:
            raise



setup(
    name='gasket',
    setup_requires=['pbr>=1.9', 'setuptools>=17.1'],
    pby=True,
    packages=find_packages()
)

if 'install' in sys.argv or 'bdist_wheel' in sys.argv:
    install_configs()
