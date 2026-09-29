from setuptools import setup
import setup_translate

pkg = 'Extensions.CrashReport'
setup(name='enigma2-plugin-extensions-crashreport',
       version='0.3',
       description='OpenATV private crash reports and receiver diagnostics',
       package_dir={pkg: 'CrashReport'},
       packages=[pkg],
       package_data={pkg: ['*.png', 'locale/*/LC_MESSAGES/*.mo']},
       data_files=[('/usr/bin', ['bin/crashreport'])],
       cmdclass=setup_translate.cmdclass,  # for translation
      )
