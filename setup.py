from setuptools import setup
    
setup(
    name = "debhelper",
    py_modules = ["debhelper"],
    scripts = ["debhelper.py"],
    version = "0.1",
    license = "LGPL",
    platforms = ['POSIX'],      # debian only..
    install_requires=["baker"],
    setup_requires=["nose"],
    description = "Setup and manage deb repo easily.",
    author = "karasuyamatengu",
    author_email = "karasuyamatengu@gmail.com",
    url = "https://github.com/tengu/debhelper",
    keywords = ["debian", "package"],
    long_description = "",
)
