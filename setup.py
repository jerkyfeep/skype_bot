import os
from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="skype_bot",
    version="0.0.2",
    author="Andrey Mironenko",
    author_email="andrey.mironenko@gmail.com",
    description="Extendable bot for Skype",
    keywords="bot skype botframework microsoft",
    url="http://github.com/amironenko/skype_bot",
    packages=['skype_bot'],
    install_requires=['PyJWT',
                          'pyOpenSSL',
                          'flask',
                          'requests', ],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
    ],
)
