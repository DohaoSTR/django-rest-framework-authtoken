from base64 import urlsafe_b64encode
from datetime import timedelta
from hashlib import sha512
from os import urandom
from typing import Optional, Union

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone

from rest_framework.response import Response
from rest_framework import status

from cylinder_head_api.celery import tasks_logger
from simple_history.models import HistoricalRecords

from .settings import AUTH_TOKEN_VALIDITY, REGISTRATION_EMAIL_CONFIRM_TOKEN_VALIDITY, AUTH_TOKEN_MAX_COUNT_ON_USER
    
class AbstractToken(models.Model):
    class Meta:
        abstract = True
        db_table = 'auth_token'

        verbose_name_plural = "авторизационные токены"
        verbose_name = "авторизационный токен"

    TOKEN_VALIDITY = AUTH_TOKEN_VALIDITY
    TOKEN_MAX_COUNT_ON_USER = AUTH_TOKEN_MAX_COUNT_ON_USER

    hashed_token = models.BinaryField(unique=True)

    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             related_name='%(class)ss',
                             on_delete=models.CASCADE,
                             verbose_name = "пользователь")

    created = models.DateTimeField(default=timezone.now, 
                                   verbose_name = "дата создания")
    
    def __str__(self) -> str:
        token_str = urlsafe_b64encode(self.hashed_token).decode()
        return '{}: {}'.format(self.user, token_str)

    @property
    def age(self) -> timedelta:
        return timezone.now() - self.created

    def logout(self, token: Union[str, None] = None):
        """
        Log this token out.
        """
        self.delete()

    @classmethod
    def create_token_for_user(cls, user: get_user_model(), **kwargs) -> Response:
        """
        Create a new random auth token for user.
        """
        tokens_count = cls.get_tokens_count(user)
        if (tokens_count + 1 > cls.TOKEN_MAX_COUNT_ON_USER):
            delete_count = tokens_count - cls.TOKEN_MAX_COUNT_ON_USER + 1

            if delete_count > 0:
                for _ in range(delete_count):
                    cls.delete_oldest_token(user)

        token = urandom(48)

        duplicate_exists = cls.objects.filter(hashed_token = token).exists()

        if duplicate_exists == False:
            cls.objects.create(
                hashed_token=cls._hash_token(token),
                user=user,
                **kwargs)
                
            return Response({'token': token}, status=status.HTTP_200_OK)
        else:
            error_message = "Ошибка при создании токена!"
            return Response(error_message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @classmethod
    def get_user_for_token(cls, token: bytes) -> Optional[get_user_model()]:
        auth_token = cls.get_token(token)
        if auth_token:
            return auth_token.user

    @classmethod
    def get_token(cls, token: bytes) -> Optional['AbstractToken']:
        try:
            auth_token = cls.objects.select_related('user').get(
                hashed_token=cls._hash_token(token))

            if auth_token.age > cls.TOKEN_VALIDITY:
                # token expired.
                auth_token.delete()
                return None

            return auth_token
        except cls.DoesNotExist:
            return None

    @classmethod
    def clear_expired_tokens(cls) -> int:
        """
        Clear tokens that are expired.
        """
        valid_min_creation = timezone.now() - cls.TOKEN_VALIDITY
        deleted_count, detail = cls.objects.filter(created__lt=valid_min_creation).delete()

        return deleted_count
    
    @classmethod
    def clear_expired_tokens(cls, user: get_user_model()) -> int:
        """
        Clear tokens that are expired.
        """
        valid_min_creation = timezone.now() - cls.TOKEN_VALIDITY
        deleted_count, detail = cls.objects.filter(created__lt=valid_min_creation, user=user).delete()

        return deleted_count

    @classmethod    
    def get_tokens_count(cls, user: get_user_model()) -> int:
        return cls.objects.filter(user=user).count()
    
    @classmethod
    def clear_tokens(cls, user: get_user_model()) -> int:
        deleted_count, detail = cls.objects.filter(user=user).delete()

        return deleted_count
    
    @classmethod
    def delete_oldest_token(cls, user: get_user_model()):
        oldest_token = cls.objects.filter(user=user).order_by('created').first()
        if oldest_token:
            oldest_token.delete()

    @staticmethod
    def _hash_token(token: bytes) -> bytes:
        """
        Hash a token.
        """
        return sha512(token).digest()

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

class AuthToken(AbstractToken):
    history = HistoricalRecords()

class EmailConfirmationToken(AbstractToken):
    class Meta:
        db_table = 'email_confirmation_token'

    TOKEN_VALIDITY = REGISTRATION_EMAIL_CONFIRM_TOKEN_VALIDITY

    email = models.EmailField()

    @classmethod
    def create_token_for_user(cls, user: get_user_model()) -> bytes:
        return super().create_token_for_user(user, email=user.email)