from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from .models import UserProfile


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Perfil'
    fields = ('role',)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'get_is_active')
    list_filter = ('role',)
    search_fields = ('user__username', 'user__email')

    def get_is_active(self, obj):
        return obj.user.is_active
    get_is_active.boolean = True
    get_is_active.short_description = 'Activo'


class CustomUserAdmin(UserAdmin):
    inlines = (UserProfileInline,)
    list_display = ('username', 'email', 'get_role', 'is_active', 'is_staff', 'date_joined')
    list_filter = ('profile__role', 'is_active', 'is_staff')

    def get_role(self, obj):
        profile = getattr(obj, 'profile', None)
        return profile.get_role_display() if profile else '—'
    get_role.short_description = 'Rol'


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
