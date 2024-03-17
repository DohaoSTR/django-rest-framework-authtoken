from rest_authtoken.models import AuthToken
from django.utils import timezone

from cylinder_head_api.celery import app
from cylinder_head_api.celery import tasks_logger

from .settings import AUTH_TOKEN_VALIDITY

@app.task()
def delete_expired_tokens():
    valid_min_creation = timezone.now() - AUTH_TOKEN_VALIDITY
    objects_to_delete = AuthToken.objects.filter(created__lt=valid_min_creation)
    deleted_count, _ = objects_to_delete.delete()
    tasks_logger.info(f"Кол-во удаленных токенов - {deleted_count}.")