import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

    # allow setup.py to be run from any path
    os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

    setup(
        name='django-amc',
        version='0.1',
        packages=find_packages(),
        include_package_data=True,
        license='BSD License', # follow the Django
        description='A Django models for Apple profile configuration.',
        long_description=README,
        url='https://github.com/chamaken/django-amc/',
        author='Ken-ichirou MATSUZAWA',
        author_email='chamaken@gmail.com',
        classifiers=[
            'Environment :: Web Environment',
            'Framework :: Django',
            'Framework :: Django :: 1.11',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: BSD License',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3.5',
            'Topic :: Internet :: WWW/HTTP',
            'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        ],
    )
