from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Libro
from config import Config
from functools import wraps
from decimal import Decimal

app = Flask(__name__)
app.config.from_object(Config)

# Inicializar extensiones
db.init_app(app)

with app.app_context():
    db.create_all()

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

        # Buscar usuario por username
        user = User.query.filter(
            (User.username == username)
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

        if not password:
            errores.append('La contraseña es obligatoria')
        elif len(password) < 6:
            errores.append('La contraseña debe tener al menos 6 caracteres')

        if password != confirm_password:
            errores.append('Las contraseñas no coinciden')

        # 2. Verificar que no existan usuarios con mismo username
        usuario_existe = User.query.filter(
            (User.username == username)
        ).first()

        if usuario_existe:
            if usuario_existe.username == username:
                errores.append(f'El usuario "{username}" ya existe')

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
        nuevo_role = request.form.get('role', 'vendedor')

        # Validaciones básicas
        if not nuevo_username or len(nuevo_username) < 3:
            flash('El nombre de usuario debe tener al menos 3 caracteres', 'danger')
            return render_template('editar_usuario.html', usuario=usuario)

        # Verificar que no haya conflicto con otros usuarios
        conflicto = User.query.filter(
            (User.username == nuevo_username) &
            (User.id != user_id)
        ).first()

        if conflicto:
            flash('Ya existe otro usuario con ese nombre de usuario', 'danger')
            return render_template('editar_usuario.html', usuario=usuario)

        usuario.username = nuevo_username
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


# ============================================
# GESTIÓN DE LIBROS (Admin y Bodega)
# ============================================

@app.route('/libros')
@login_required
def listar_libros():
    """Muestra todos los libros (admin y bodega pueden ver)"""
    # Verificar rol
    if current_user.role not in ['admin', 'bodega']:
        flash('Acceso denegado. Solo administradores y personal de bodega pueden ver los libros.', 'danger')
        return redirect(url_for('dashboard'))

    # Obtener todos los libros ordenados por nombre
    libros = Libro.query.order_by(Libro.nombre).all()

    # Estadísticas
    total_libros = len(libros)
    total_ejemplares = sum(libro.existencias for libro in libros)
    libros_agotados = sum(1 for libro in libros if libro.existencias == 0)

    return render_template('libros/listar_libros.html',
                           libros=libros,
                           total_libros=total_libros,
                           total_ejemplares=total_ejemplares,
                           libros_agotados=libros_agotados)

@app.route('/libros/crear', methods=['GET', 'POST'])
@login_required
def crear_libro():
    """Crear un nuevo libro (admin y bodega pueden crear)"""
    if current_user.role not in ['admin', 'bodega']:
        flash('Acceso denegado. Solo administradores y personal de bodega pueden crear libros.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        precio = request.form.get('precio', '').strip()
        autor = request.form.get('autor', '').strip()
        existencias = request.form.get('existencias', 0)

        # ============================================
        # VALIDACIÓN DE PRECIO (con dos decimales)
        # ============================================
        errores = []

        # Validar precio
        if not precio:
            errores.append('El precio es obligatorio')
        else:
            try:
                # Convertir a float
                precio = float(precio)

                # Validar que sea positivo
                if precio < 0:
                    errores.append('El precio no puede ser negativo')

                # Validar que solo tenga 2 decimales usando Decimal
                from decimal import Decimal, InvalidOperation
                precio_decimal = Decimal(precio)

                # Verificar que no tenga más de 2 decimales
                if precio_decimal.as_tuple().exponent < -2:
                    errores.append('El precio solo puede tener hasta 2 decimales (ejemplo: 19.99)')

            except (ValueError, InvalidOperation):
                errores.append('El precio debe ser un número válido (ejemplo: 19.99)')

        if not nombre:
            errores.append('El nombre del libro es obligatorio')
        elif len(nombre) < 3:
            errores.append('El nombre debe tener al menos 3 caracteres')

        if not precio:
            errores.append('El precio es obligatorio')

        if not autor:
            errores.append('El autor es obligatorio')

        try:
            existencias = int(existencias)
            if existencias < 0:
                errores.append('Las existencias no pueden ser negativas')
        except ValueError:
            errores.append('Las existencias deben ser un número válido')

        # Verificar si ya existe un libro con el mismo nombre y autor
        libro_existe = Libro.query.filter_by(nombre=nombre, autor=autor).first()
        if libro_existe:
            errores.append(f'Ya existe un libro con el nombre "{nombre}" del autor "{autor}"')

        if errores:
            for error in errores:
                flash(error, 'danger')
            return render_template('libros/crear_libro.html')

        try:
            nuevo_libro = Libro(
                nombre=nombre,
                precio=precio,
                autor=autor,
                existencias=existencias,
                creado_por_id=current_user.id,
                editado_por_id=current_user.id
            )
            db.session.add(nuevo_libro)
            db.session.commit()
            flash(f'✅ Libro "{nombre}" creado exitosamente', 'success')
            return redirect(url_for('listar_libros'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear libro: {str(e)}', 'danger')

    return render_template('libros/crear_libro.html')


@app.route('/libros/editar/<int:libro_id>', methods=['GET', 'POST'])
@login_required
def editar_libro(libro_id):
    """Editar un libro (admin y bodega pueden editar existencias)"""
    if current_user.role not in ['admin', 'bodega']:
        flash('Acceso denegado. Solo administradores y personal de bodega pueden editar libros.', 'danger')
        return redirect(url_for('dashboard'))

    libro = Libro.query.get_or_404(libro_id)

    if request.method == 'POST':
        # Solo admin puede cambiar nombre, autor
        if current_user.role == 'admin':
            libro.nombre = request.form.get('nombre', '').strip()
            libro.autor = request.form.get('autor', '').strip()

        # Ambos pueden cambiar existencias
        try:
            nuevas_existencias = int(request.form.get('existencias', 0))
            if nuevas_existencias < 0:
                flash('Las existencias no pueden ser negativas', 'danger')
                return render_template('libros/editar_libro.html', libro=libro)
            libro.existencias = nuevas_existencias
        except ValueError:
            flash('Las existencias deben ser un número válido', 'danger')
            return render_template('libros/editar_libro.html', libro=libro)

        libro.editado_por_id = current_user.id

        try:
            db.session.commit()
            flash(f'✅ Libro "{libro.nombre}" actualizado correctamente', 'success')
            return redirect(url_for('listar_libros'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar libro: {str(e)}', 'danger')

    return render_template('libros/editar_libro.html', libro=libro)


@app.route('/libros/eliminar/<int:libro_id>', methods=['GET', 'POST'])
@login_required
def eliminar_libro(libro_id):
    """Eliminar un libro (SOLO ADMIN, con confirmación de contraseña)"""
    if current_user.role != 'admin':
        flash('Acceso denegado. Solo los administradores pueden eliminar libros.', 'danger')
        return redirect(url_for('dashboard'))

    libro = Libro.query.get_or_404(libro_id)

    if request.method == 'POST':
        password = request.form.get('password', '')

        # Verificar contraseña del admin
        if not current_user.check_password(password):
            flash('❌ Contraseña incorrecta. No se eliminó el libro.', 'danger')
            return render_template('libros/eliminar_libro.html', libro=libro)

        nombre_libro = libro.nombre

        try:
            db.session.delete(libro)
            db.session.commit()
            flash(f'✅ Libro "{nombre_libro}" eliminado permanentemente', 'success')
            return redirect(url_for('listar_libros'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al eliminar libro: {str(e)}', 'danger')

    return render_template('libros/eliminar_libro.html', libro=libro)


@app.route('/libros/actualizar-stock', methods=['POST'])
@login_required
def actualizar_stock():
    """Actualización rápida de stock (para bodega y admin)"""
    if current_user.role not in ['admin', 'bodega']:
        flash('Acceso denegado', 'danger')
        return redirect(url_for('dashboard'))

    libro_id = request.form.get('libro_id')
    operacion = request.form.get('operacion')  # 'sumar' o 'restar'
    cantidad = request.form.get('cantidad', 1)

    libro = Libro.query.get_or_404(libro_id)

    try:
        cantidad = int(cantidad)
        if cantidad <= 0:
            flash('La cantidad debe ser mayor a 0', 'danger')
            return redirect(url_for('listar_libros'))

        if operacion == 'sumar':
            libro.existencias += cantidad
            flash(f'✅ Se agregaron {cantidad} ejemplares de "{libro.nombre}"', 'success')
        elif operacion == 'restar':
            if libro.existencias - cantidad < 0:
                flash(f'❌ No hay suficientes existencias. Stock actual: {libro.existencias}', 'danger')
                return redirect(url_for('listar_libros'))
            libro.existencias -= cantidad
            flash(f'✅ Se retiraron {cantidad} ejemplares de "{libro.nombre}"', 'success')
        else:
            flash('Operación no válida', 'danger')
            return redirect(url_for('listar_libros'))

        libro.editado_por_id = current_user.id
        db.session.commit()

    except ValueError:
        flash('Cantidad no válida', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'danger')

    return redirect(url_for('listar_libros'))

# ============================================
# MÓDULO DE VENTAS
# ============================================

@app.route('/ventas')
@login_required
def panel_ventas():
    """Panel principal de ventas (vendedores y admin)"""
    if current_user.role not in ['admin', 'vendedor']:
        flash('Acceso denegado. Solo administradores y vendedores pueden acceder al módulo de ventas.', 'danger')
        return redirect(url_for('dashboard'))

    # Obtener libros disponibles (con existencias > 0)
    libros_disponibles = Libro.query.filter(Libro.existencias > 0).order_by(Libro.nombre).all()

    return render_template('ventas/panel_ventas.html', libros=libros_disponibles)


@app.route('/ventas/datos-cliente', methods=['POST'])
@login_required
def datos_cliente():
    """Recibe los libros seleccionados y muestra el formulario de datos del cliente"""
    if current_user.role not in ['admin', 'vendedor']:
        flash('Acceso denegado', 'danger')
        return redirect(url_for('dashboard'))

    libro_ids = request.form.getlist('libro_id')

    if not libro_ids:
        flash('⚠️ Selecciona al menos un libro para continuar.', 'warning')
        return redirect(url_for('panel_ventas'))

    items = []
    for libro_id in libro_ids:
        cantidad = int(request.form.get(f'cantidad_{libro_id}', 1))
        libro = Libro.query.get(libro_id)
        if libro and 0 < cantidad <= libro.existencias:
            items.append({
                'id': libro.id,
                'nombre': libro.nombre,
                'precio': float(libro.precio),
                'cantidad': cantidad
            })

    if not items:
        flash('⚠️ No se pudieron agregar los libros seleccionados.', 'warning')
        return redirect(url_for('panel_ventas'))

    session['venta_items'] = items
    session.modified = True

    total = sum(item['precio'] * item['cantidad'] for item in items)
    return render_template('ventas/datos_cliente.html', items=items, total=total)


@app.route('/ventas/finalizar', methods=['POST'])
@login_required
def finalizar_venta():
    """Finaliza la venta con datos del cliente y actualiza el inventario"""
    if current_user.role not in ['admin', 'vendedor']:
        flash('Acceso denegado', 'danger')
        return redirect(url_for('dashboard'))

    items = session.get('venta_items', [])

    if not items:
        flash('⚠️ No hay items para procesar. Inicia una nueva venta.', 'warning')
        return redirect(url_for('panel_ventas'))

    nombre_cliente = request.form.get('nombre_cliente', '').strip()
    telefono_cliente = request.form.get('telefono_cliente', '').strip()

    if not nombre_cliente:
        flash('⚠️ El nombre del cliente es requerido.', 'warning')
        total = sum(item['precio'] * item['cantidad'] for item in items)
        return render_template('ventas/datos_cliente.html', items=items, total=total,
                               nombre_cliente=nombre_cliente, telefono_cliente=telefono_cliente)

    try:
        for item in items:
            libro = Libro.query.get(item['id'])
            if libro:
                libro.existencias -= item['cantidad']
                libro.editado_por_id = current_user.id

        db.session.commit()

        session.pop('venta_items', None)
        session.modified = True

        flash(f'✅ Venta completada exitosamente para {nombre_cliente}.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'❌ Error al procesar la venta: {str(e)}', 'danger')

    return redirect(url_for('panel_ventas'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)