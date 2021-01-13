from wtforms.validators import DataRequired, EqualTo
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, TextField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Email


class RegisterForm(FlaskForm):
    login = StringField(
        'Login:',
        [
            DataRequired(message='Wpisz swój login.')
        ]
    )
    email = StringField(
        'Email:',
        [
            Email(message='Niepoprawny adres email.'),
            DataRequired(message='Wpisz email.')
         ]
    )
    password = PasswordField(
        'Hasło:',
        [
            DataRequired(message='Wpisz hasło.'),
            Length(min=8,
                   message='Twoje hasło jest za krótkie.')
        ]
    )
    password_repeat = PasswordField(
        'Powtórz hasło:',
        [
            EqualTo('password', message='Hasła muszą się zgadzać.')
        ]
    )
    # recaptha = RecaptchaField()
    submit = SubmitField('Utwórz konto')


class LoginForm(FlaskForm):
    login = StringField(
        'Login:',
        [
            DataRequired(message='Podaj swój login')
        ]
    )
    password = PasswordField(
        'Hasło:',
        [
            DataRequired(message='Podaj swoje hasło')
        ]
    )
    submit = SubmitField('Zaloguj')
