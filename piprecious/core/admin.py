from django.contrib import admin

from core.models import *


@admin.register(APKFile)
class APKFileModelAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj = None):
        if obj:
            return self.readonly_fields + ('id', 'sha256', 'size')
        return self.readonly_fields


@admin.register(PCAPFile)
class PCAPFileModelAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj = None):
        if obj:
            return self.readonly_fields + ('id', 'sha256', 'size')
        return self.readonly_fields


@admin.register(FlowFile)
class FlowFileModelAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj = None):
        if obj:
            return self.readonly_fields + ('id', 'sha256', 'size')
        return self.readonly_fields


@admin.register(BluetoothDump)
class BluetoothDumpModelAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj = None):
        if obj:
            return self.readonly_fields + ('id', 'sha256', 'size')
        return self.readonly_fields


@admin.register(Application)
class ApplicationModelAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj = None):
        if obj:
            return self.readonly_fields + (
                'id', 'name', 'handle', 'version_code', 'version_name', 'icon_phash', 'app_uid', 'creator')
        return self.readonly_fields


@admin.register(IoTDevice)
class IoTDeviceModelAdmin(admin.ModelAdmin):
    pass


@admin.register(Smartphone)
class SmartphoneModelAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj = None):
        if obj:
            return self.readonly_fields + ('id', 'serial', 'raw_parameters')
        return self.readonly_fields


@admin.register(Session)
class SessionModelAdmin(admin.ModelAdmin):
    pass


@admin.register(Experiment)
class ExperimentModelAdmin(admin.ModelAdmin):
    pass


@admin.register(NetworkAnalysis)
class NetworkAnalysisModelAdmin(admin.ModelAdmin):
    pass


@admin.register(DNSQuery)
class DNSQueryModelAdmin(admin.ModelAdmin):
    pass


# @admin.register(Domain)
# class DomainModelAdmin(admin.ModelAdmin):
#     pass
#
#
# @admin.register(IpAddress)
# class IpAddressModelAdmin(admin.ModelAdmin):
#     pass
