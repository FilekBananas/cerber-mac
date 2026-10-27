# Inert YARA fixture for CERBER_MacOS_Dyld_Insert_Libraries_Tmp - text only, not a working sample.
launchctl setenv DYLD_INSERT_LIBRARIES /tmp/fixture.dylib
echo 'export DYLD_INSERT_LIBRARIES=/tmp/fixture.dylib' >> ~/.zshrc
