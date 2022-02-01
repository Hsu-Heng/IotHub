from django.conf import settings
import factory
import factory.fuzzy

DEFAULT_TEST_PASSWORD = "secret"


class UserFactory(factory.django.DjangoModelFactory):
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    username = factory.Sequence(lambda n: 'user-{0}'.format(n))
    email = factory.LazyAttribute(lambda a: f'{a.first_name.lower().replace(" ", ".")}@example.com')
    password = factory.PostGenerationMethodCall('set_password', DEFAULT_TEST_PASSWORD)
    role = "Admin"

    class Meta:
        model = settings.AUTH_USER_MODEL