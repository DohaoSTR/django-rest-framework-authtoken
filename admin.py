from base64 import urlsafe_b64encode

from django.contrib import admin
from django.contrib import messages

from cylinder_head_api.celery import tasks_logger

from .models import AuthToken

from simple_history.admin import SimpleHistoryAdmin

class AuthTokenAdmin(SimpleHistoryAdmin):
    list_display = ('user', 'created')
    exclude = ('created',)
    actions = ['delete_selected']

    def delete_selected(self, request, queryset):
        for obj in queryset:
            obj.delete()

    delete_selected.short_description = 'Удалить выбранные токены'

    def message_user(self, request, message, level=messages.INFO, extra_tags='',
                    fail_silently=False):
        pass

    def save_model(self, request, obj, form, change):
        token_response = AuthToken.create_token_for_user(request.user)
        if token_response.status_code // 100 == 2:
            token = token_response.data.get('token')
            token_str = urlsafe_b64encode(token).decode()
            messages.success(request, f"Токен успешно создан: {token_str}")
        else:
            messages.error(request, "Ошибка при создании токена")

    def has_change_permission(self, request, obj=None):
        return False

admin.site.register(AuthToken, AuthTokenAdmin)