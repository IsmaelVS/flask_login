# coding: utf-8
"""Projeto web utilizando Flask e Flask-login."""


from flask import Flask, render_template, request
from flask_login import login_required, login_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from wtforms import Form, PasswordField, StringField, SubmitField

app = Flask(__name__)

app.config['SECRET_KEY'] = 'teste'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app)


class Usuario(db.Model):
    """Classe para criação da tabela usuário no banco."""

    __tablename__ = 'usuario'

    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean, default=False, nullable=False)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return not self.is_authenticated()

    def get_id(self):
        return chr(self.id)

    def __init__(self, username, password, admin):
        db.create_all()
        self.username = username
        self.password = password
        self.admin = admin

    def __repr__(self):
        return """
        Usuario(username={}, password={}, admin={})""".format(
            self.username, self.password, self.admin)


class Login(Form):
    """Classe para montar o formulário."""

    login = StringField('Username')
    password = PasswordField('Password')
    btn = SubmitField('Logar')


class Cadastro(Form):
    """Classe para montar o formulário de cadastro."""

    login = StringField('Username')
    password = PasswordField('Password')
    btn = SubmitField('Cadastrar')


@app.route('/login')
def login():
    """Rota inicial, exibe o template do formulário."""
    return render_template('login.html', form=Login())


@app.route('/check_login', methods=['POST'])
def check_login():
    """Rota para validar dados do formulário."""
    if validate_login(user=request.form['username'],
                      senha=request.form['password']):
        login_user(True)
        return 'Deu bom!'
    return 'Usuário ou senha inválido!'


def validate_login(user, senha):
    """Função de validação dos dados do formulário."""
    return db.session.query(Usuario).filter_by(
        username=user, password=senha).first()


@app.route('/')
def home():
    """Rota inicial, com formulário para cadastro."""
    return render_template('cadastro.html', form=Cadastro())


@app.route('/checar_cadastro', methods=['POST'])
def checar_cadastro():
    """Rota para checar cadastro."""
    username = request.form['login']
    hashed_password = generate_password_hash(
        request.form['password'], method='sha256')
    user = Usuario(
        username=username,
        password=hashed_password,
        admin=True)
    db.session.add(user)
    db.session.commit()
    return render_template('login.html', form=Login())


@app.route('/logado')
@login_required
def logado(current_user):
    """Rota inicial após a realização de login."""
    return 'Logado com sucesso!!'


if __name__ == '__main__':
    app.run(debug=True)
