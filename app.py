from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User
from config import Config
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)

# Inicializar extensiones
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Si no está logueado, redirige aquí
login_manager.login_message = 'Por favor inicia sesión para acceder'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Ruta para el login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Buscar usuario por username o email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f'¡Bienvenido {user.username}!', 'success')

            # Redirigir según el rol
            if user.role == 'admin':
                return redirect(url_for('dashboard'))
            elif user.role == 'vendedor':
                return redirect(url_for('dashboard'))
            elif user.role == 'bodega':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')


# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('login'))


# Dashboard principal (protegido)
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    # Puedes pasar el rol al template para mostrar diferentes vistas
    return render_template('dashboard.html', user=current_user)


# Crear un usuario de prueba (solo para desarrollo)
@app.route('/crear-admin')
def crear_admin():
    # Verificar si ya existe
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@jurislib.com',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        return 'Usuario admin creado con contraseña: admin123'
    return 'El usuario admin ya existe'


# ============================================
# DECORADOR PARA CONTROL DE ROLES
# ============================================

def role_required(allowed_roles):
    """
    Decorador para verificar que el usuario tenga el rol permitido.

    Uso:
        @role_required(['admin', 'vendedor'])
        @app.route('/algo')
        def algo():
            ...
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Verificar que hay un usuario logueado
            if not current_user.is_authenticated:
                flash('Debes iniciar sesión para acceder', 'warning')
                return redirect(url_for('login'))

            # Verificar el rol
            if current_user.role not in allowed_roles:
                flash(f'Acceso denegado. Se requiere rol: {", ".join(allowed_roles)}', 'danger')
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f):
    """Versión simplificada solo para admin"""
    return role_required(['admin'])(f)


# ============================================
# GESTIÓN DE USUARIOS (SOLO ADMIN)
# ============================================

@app.route('/usuarios')
@admin_required
def listar_usuarios():
    """
    Muestra todos los usuarios del sistema (solo admin)
    """
    # Obtener todos los usuarios ordenados por ID
    usuarios = User.query.order_by(User.id).all()

    # Estadísticas
    total_usuarios = len(usuarios)
    admins = sum(1 for u in usuarios if u.role == 'admin')
    vendedores = sum(1 for u in usuarios if u.role == 'vendedor')
    bodegas = sum(1 for u in usuarios if u.role == 'bodega')

    return render_template('listar_usuarios.html',
                           usuarios=usuarios,
                           total=total_usuarios,
                           admins=admins,
                           vendedores=vendedores,
                           bodegas=bodegas)


@app.route('/crear-usuario', methods=['GET', 'POST'])
@admin_required
def crear_usuario():
    """
    Permite al administrador crear nuevos usuarios.
    GET  → Muestra el formulario
    POST → Procesa la creación
    """

    if request.method == 'POST':
        # Obtener datos del formulario
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'vendedor')

        # Validaciones
        errores = []

        # 1. Validar campos requeridos
        if not username:
            errores.append('El nombre de usuario es obligatorio')
        elif len(username) < 3:
            errores.append('El nombre de usuario debe tener al menos 3 caracteres')

        if not email:
            errores.append('El email es obligatorio')
        elif '@' not in email:
            errores.append('Email inválido (debe contener @)')

        if not password:
            errores.append('La contraseña es obligatoria')
        elif len(password) < 6:
            errores.append('La contraseña debe tener al menos 6 caracteres')

        if password != confirm_password:
            errores.append('Las contraseñas no coinciden')

        # 2. Verificar que no existan usuarios con mismo username o email
        usuario_existe = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if usuario_existe:
            if usuario_existe.username == username:
                errores.append(f'El usuario "{username}" ya existe')
            if usuario_existe.email == email:
                errores.append(f'El email "{email}" ya está registrado')

        # 3. Verificar que el rol sea válido
        roles_validos = ['admin', 'vendedor', 'bodega']
        if role not in roles_validos:
            errores.append(f'Rol inválido. Debe ser: {", ".join(roles_validos)}')

        # Si hay errores, mostrarlos y volver al formulario
        if errores:
            for error in errores:
                flash(error, 'danger')
            return render_template('crear_usuario.html')

        # Crear el nuevo usuario
        try:
            nuevo_usuario = User(
                username=username,
                email=email,
                role=role
            )
            nuevo_usuario.set_password(password)

            db.session.add(nuevo_usuario)
            db.session.commit()

            flash(f'✅ Usuario "{username}" creado exitosamente con rol "{role}"', 'success')
            return redirect(url_for('listar_usuarios'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear usuario: {str(e)}', 'danger')
            return render_template('crear_usuario.html')

    # Método GET: mostrar formulario vacío
    return render_template('crear_usuario.html')


@app.route('/usuario/editar/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def editar_usuario(user_id):
    """
    Editar un usuario existente
    """
    usuario = User.query.get_or_404(user_id)

    # No permitir editar el propio admin (seguridad)
    if usuario.id == current_user.id:
        flash('No puedes editar tu propio usuario desde aquí', 'warning')
        return redirect(url_for('listar_usuarios'))

    if request.method == 'POST':
        # Actualizar campos
        nuevo_username = request.form.get('username', '').strip()
        nuevo_email = request.form.get('email', '').strip()
        nuevo_role = request.form.get('role', 'vendedor')

        # Validaciones básicas
        if not nuevo_username or len(nuevo_username) < 3:
            flash('El nombre de usuario debe tener al menos 3 caracteres', 'danger')
            return render_template('editar_usuario.html', usuario=usuario)

        if not nuevo_email or '@' not in nuevo_email:
            flash('Email inválido', 'danger')
            return render_template('editar_usuario.html', usuario=usuario)

        # Verificar que no haya conflicto con otros usuarios
        conflicto = User.query.filter(
            ((User.username == nuevo_username) | (User.email == nuevo_email)) &
            (User.id != user_id)
        ).first()

        if conflicto:
            flash('Ya existe otro usuario con ese nombre de usuario o email', 'danger')
            return render_template('editar_usuario.html', usuario=usuario)

        usuario.username = nuevo_username
        usuario.email = nuevo_email
        usuario.role = nuevo_role

        # Si se proporcionó nueva contraseña, actualizarla
        nueva_password = request.form.get('password', '')
        if nueva_password:
            if len(nueva_password) >= 6:
                usuario.set_password(nueva_password)
                flash('Contraseña actualizada', 'info')
            else:
                flash('La contraseña debe tener al menos 6 caracteres (no se cambió)', 'warning')

        try:
            db.session.commit()
            flash(f'✅ Usuario "{usuario.username}" actualizado correctamente', 'success')
            return redirect(url_for('listar_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar: {str(e)}', 'danger')

    return render_template('editar_usuario.html', usuario=usuario)


@app.route('/usuario/eliminar/<int:user_id>')
@admin_required
def eliminar_usuario(user_id):
    """
    Eliminar un usuario
    """
    usuario = User.query.get_or_404(user_id)

    # No permitir eliminar el propio admin
    if usuario.id == current_user.id:
        flash('No puedes eliminar tu propio usuario', 'danger')
        return redirect(url_for('listar_usuarios'))

    nombre = usuario.username

    try:
        db.session.delete(usuario)
        db.session.commit()
        flash(f'✅ Usuario "{nombre}" eliminado correctamente', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar usuario: {str(e)}', 'danger')

    return redirect(url_for('listar_usuarios'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crea las tablas si no existen
    app.run(debug=True)