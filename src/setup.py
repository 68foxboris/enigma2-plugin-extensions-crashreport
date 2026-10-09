from setuptools import setup
from setup_translate import cmdclass

pkg = 'Extensions.CrashReporter'
setup(name='enigma2-plugin-extensions-crashreporter',
       version='0.5',
       description='OpenATV private crash reports and receiver diagnostics',
       package_dir={pkg: 'CrashReporter'},
       packages=[pkg],
       package_data={pkg: ['*.png', 'setup.xml', 'locale/*/LC_MESSAGES/*.mo']},
       data_files=[('/usr/bin', ['bin/crashreporter'])],
       cmdclass=cmdclass,  # for translation
      )
