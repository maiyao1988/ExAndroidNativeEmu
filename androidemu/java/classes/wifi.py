from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def,JavaMethodDef
from ..classes.list import List
from ..classes.string import String


class WifiConfiguration(metaclass=JavaClassDef, jvm_name='android/net/wifi/WifiConfiguration',
                  jvm_fields=[
                      JavaFieldDef('SSID', 'Ljava/lang/String;', False),
                      JavaFieldDef('hiddenSSID', 'Z', False),
                      JavaFieldDef('BSSID', 'Ljava/lang/String;', False),
                      JavaFieldDef('FQDN', 'Ljava/lang/String;', False),
                      JavaFieldDef('networkId', 'I', False),
                      JavaFieldDef('priority', 'I', False),
                      JavaFieldDef('providerFriendlyName', 'Ljava/lang/String;', False),
                      ]
                      ):
    def __init__(self):
        self.SSID = String("")
        self.BSSID=String("")
        self.FQDN=String("")
        self.hiddenSSID = False
        self.networkId = 0
        self.priority = 0
        self.providerFriendlyName = String("hello")
    #

#

class DhcpInfo(metaclass=JavaClassDef, jvm_name='android/net/DhcpInfo',
                  jvm_fields=[
                      JavaFieldDef('gateway', 'I', False),
                      ]
                      ):
    def __init__(self):
        self.gateway = 0
    #
#

class WifiManager(metaclass=JavaClassDef, jvm_name='android/net/wifi/WifiManager'):
    def __init__(self):
        self.__list = List()
        self.__dhcpInfo = DhcpInfo()
    #

    @java_method_def(name='getConfiguredNetworks', signature='()Ljava/util/List;', native=False)
    def getConfiguredNetworks(self, emu):
        return self.__list
    #

    @java_method_def(name='getDhcpInfo', signature='()Landroid/net/DhcpInfo;', native=False)
    def getDhcpInfo(self, emu):
        return self.__dhcpInfo
    #
#