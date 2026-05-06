from flask import Flask, request, jsonify, g, abort
import sqlite3
import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'teamtask.db')
SECRET = 'teamhub-secret-2025'

app = Flask(__name__)

# ---------------------------- Database Helpers ----------------------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def q(sql, args=(), one=False, commit=False):
    db = get_db()
    cur = db.execute(sql, args)
    if commit:
        db.commit()
        return cur.lastrowid
    rows = cur.fetchall()
    return (dict(rows[0]) if rows else None) if one else [dict(r) for r in rows]

def migrate_db():
    db = sqlite3.connect(DB_PATH)
    try:
        db.execute("ALTER TABLE tasks ADD COLUMN progress INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        db.execute("ALTER TABLE projects ADD COLUMN status TEXT DEFAULT 'active'")
    except sqlite3.OperationalError:
        pass
    try:
        db.execute("ALTER TABLE tasks ADD COLUMN gitlab_url TEXT")
    except sqlite3.OperationalError:
        pass
    db.executescript("""
        CREATE TABLE IF NOT EXISTS task_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            message TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    db.commit()
    db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'member',
            avatar_initials TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            owner_id INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS project_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            joined_at TEXT DEFAULT (datetime('now')),
            UNIQUE(project_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'todo',
            priority TEXT DEFAULT 'medium',
            progress INTEGER DEFAULT 0,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            assignee_id INTEGER REFERENCES users(id),
            creator_id INTEGER NOT NULL REFERENCES users(id),
            due_date TEXT,
            gitlab_url TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER NOT NULL REFERENCES users(id),
            to_user_id INTEGER NOT NULL REFERENCES users(id),
            message TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            read_at TEXT
        );
    """)
    db.commit()
    db.close()
    migrate_db()

# ---------------------------- Authentication ----------------------------
def make_token(user_id):
    exp = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
    payload = f"{user_id}:{exp}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def verify_token(token):
    try:
        parts = token.split(':')
        user_id, exp, sig = parts[0], parts[1], parts[2]
        expected = hmac.new(SECRET.encode(), f"{user_id}:{exp}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp) < datetime.now(timezone.utc).timestamp():
            return None
        return int(user_id)
    except Exception:
        return None

def jwt_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '') if auth.startswith('Bearer ') else None
        if not token:
            return jsonify({'error': 'Token required'}), 401
        uid = verify_token(token)
        if not uid:
            return jsonify({'error': 'Invalid or expired token'}), 401
        g.current_user_id = uid
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = q('SELECT role FROM users WHERE id=?', [g.current_user_id], one=True)
        if not user or user['role'] != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def hash_pw(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
    return f"{salt}:{h.hex()}"

def check_pw(pw, stored):
    try:
        salt, h = stored.split(':')
        return hmac.compare_digest(
            hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex(),
            h
        )
    except Exception:
        return False

def user_to_dict(u):
    return {k: u[k] for k in ['id', 'name', 'email', 'role', 'avatar_initials', 'created_at'] if k in u}

# ---------------------------- Project / Task helpers ----------------------------
def project_stats(pid):
    tasks = q('SELECT status, progress FROM tasks WHERE project_id=?', [pid])
    total = len(tasks)
    done = sum(1 for t in tasks if t['status'] == 'done')
    progress = round(done / total * 100) if total else 0
    avg_progress = sum(t['progress'] for t in tasks) // total if total else 0
    members = q('SELECT COUNT(*) as c FROM project_members WHERE project_id=?', [pid], one=True)['c']
    return total, done, progress, members + 1, avg_progress

def enrich_project(p):
    total, done, prog, mem, avg_prog = project_stats(p['id'])
    return {**p, 'total_tasks': total, 'completed_tasks': done, 'progress': prog,
            'member_count': mem, 'avg_progress': avg_prog}

def user_project_ids(uid):
    owned = [r['id'] for r in q('SELECT id FROM projects WHERE owner_id=?', [uid])]
    member = [r['project_id'] for r in q('SELECT project_id FROM project_members WHERE user_id=?', [uid])]
    return list(set(owned + member))

def _check_access(project, uid):
    if project['owner_id'] == uid:
        return
    if q('SELECT id FROM project_members WHERE project_id=? AND user_id=?', [project['id'], uid], one=True):
        return
    user = q('SELECT role FROM users WHERE id=?', [uid], one=True)
    if user and user['role'] == 'admin':
        return
    abort(403)

def task_to_dict(t):
    now = datetime.now(timezone.utc)
    overdue = False
    if t.get('due_date') and t['status'] != 'done':
        try:
            due = datetime.fromisoformat(t['due_date'].replace('Z', '+00:00'))
            if due.tzinfo is None:
                due = due.replace(tzinfo=timezone.utc)
            overdue = due < now
        except Exception:
            pass
    assignee = q('SELECT name, avatar_initials FROM users WHERE id=?', [t['assignee_id']], one=True) if t.get('assignee_id') else None
    creator = q('SELECT name FROM users WHERE id=?', [t['creator_id']], one=True)
    proj = q('SELECT name FROM projects WHERE id=?', [t['project_id']], one=True)
    return {
        **{k: t[k] for k in ['id', 'title', 'description', 'status', 'priority',
                             'project_id', 'assignee_id', 'creator_id', 'due_date',
                             'created_at', 'progress', 'gitlab_url']},
        'is_overdue': overdue,
        'assignee_name': assignee['name'] if assignee else None,
        'assignee_initials': assignee['avatar_initials'] if assignee else None,
        'creator_name': creator['name'] if creator else None,
        'project_name': proj['name'] if proj else None,
        'remaining': 100 - t.get('progress', 0)
    }

# ---------------------------- Auth Routes ----------------------------
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    if not all(k in data for k in ['name', 'email', 'password']):
        return jsonify({'error': 'Name, email, password required'}), 400
    email = data['email'].strip().lower()
    if q('SELECT id FROM users WHERE email=?', [email], one=True):
        return jsonify({'error': 'Email already registered'}), 409
    initials = ''.join(w[0].upper() for w in data['name'].split()[:2])
    uid = q('INSERT INTO users(name, email, password_hash, role, avatar_initials) VALUES(?,?,?,?,?)',
            [data['name'], email, hash_pw(data['password']), data.get('role', 'member'), initials],
            commit=True)
    user = q('SELECT * FROM users WHERE id=?', [uid], one=True)
    return jsonify({'token': make_token(uid), 'user': user_to_dict(user)}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    user = q('SELECT * FROM users WHERE email=?', [email], one=True)
    if not user or not check_pw(data.get('password', ''), user['password_hash']):
        return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'token': make_token(user['id']), 'user': user_to_dict(user)})

@app.route('/api/auth/me')
@jwt_required
def me():
    user = q('SELECT * FROM users WHERE id=?', [g.current_user_id], one=True)
    return jsonify(user_to_dict(user))

# ---------------------------- Project Routes ----------------------------
@app.route('/api/projects')
@jwt_required
def get_projects():
    ids = user_project_ids(g.current_user_id)
    if not ids:
        return jsonify([])
    ph = ','.join('?' * len(ids))
    projects = q(f'SELECT * FROM projects WHERE id IN ({ph})', ids)
    return jsonify([enrich_project(p) for p in projects])

@app.route('/api/projects', methods=['POST'])
@jwt_required
@admin_required
def create_project():
    data = request.get_json() or {}
    if not data.get('name'):
        return jsonify({'error': 'Project name required'}), 400
    pid = q('INSERT INTO projects(name, description, owner_id) VALUES(?,?,?)',
            [data['name'], data.get('description', ''), g.current_user_id], commit=True)
    project = q('SELECT * FROM projects WHERE id=?', [pid], one=True)
    return jsonify(enrich_project(project)), 201

@app.route('/api/projects/<int:pid>')
@jwt_required
def get_project(pid):
    project = q('SELECT * FROM projects WHERE id=?', [pid], one=True)
    if not project:
        return jsonify({'error': 'Not found'}), 404
    _check_access(project, g.current_user_id)
    enriched = enrich_project(project)
    members = q('''
        SELECT u.id, u.name, u.email, u.avatar_initials,
               (p.owner_id = u.id) as is_owner
        FROM users u
        LEFT JOIN project_members pm ON u.id = pm.user_id AND pm.project_id = ?
        JOIN projects p ON p.id = ?
        WHERE (pm.project_id = ? OR p.owner_id = u.id) AND p.id = ?
        GROUP BY u.id
    ''', [pid, pid, pid, pid])
    enriched['members'] = members
    return jsonify(enriched)

@app.route('/api/projects/<int:pid>', methods=['PUT'])
@jwt_required
def update_project(pid):
    project = q('SELECT * FROM projects WHERE id=?', [pid], one=True)
    if not project:
        return jsonify({'error': 'Not found'}), 404
    if project['owner_id'] != g.current_user_id:
        user = q('SELECT role FROM users WHERE id=?', [g.current_user_id], one=True)
        if user['role'] != 'admin':
            abort(403)
    data = request.get_json() or {}
    q('UPDATE projects SET name=?, description=?, status=?, updated_at=? WHERE id=?',
      [data.get('name', project['name']), data.get('description', project['description']),
       data.get('status', project['status']), datetime.now(timezone.utc).isoformat(), pid],
      commit=True)
    updated = q('SELECT * FROM projects WHERE id=?', [pid], one=True)
    return jsonify(enrich_project(updated))

@app.route('/api/projects/<int:pid>', methods=['DELETE'])
@jwt_required
def delete_project(pid):
    project = q('SELECT * FROM projects WHERE id=?', [pid], one=True)
    if not project:
        return jsonify({'error': 'Not found'}), 404
    if project['owner_id'] != g.current_user_id:
        user = q('SELECT role FROM users WHERE id=?', [g.current_user_id], one=True)
        if user['role'] != 'admin':
            abort(403)
    q('DELETE FROM projects WHERE id=?', [pid], commit=True)
    return jsonify({'message': 'Project deleted'}), 200

@app.route('/api/projects/<int:pid>/members', methods=['POST'])
@jwt_required
def add_project_member(pid):
    project = q('SELECT * FROM projects WHERE id=?', [pid], one=True)
    if not project:
        return jsonify({'error': 'Not found'}), 404
    if project['owner_id'] != g.current_user_id:
        user = q('SELECT role FROM users WHERE id=?', [g.current_user_id], one=True)
        if user['role'] != 'admin':
            abort(403)
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    user = q('SELECT id FROM users WHERE email=?', [email], one=True)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    try:
        q('INSERT INTO project_members(project_id, user_id) VALUES(?,?)', [pid, user['id']], commit=True)
        return jsonify({'message': 'Member added successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User already in project'}), 409

# ---------------------------- Task Routes ----------------------------
@app.route('/api/projects/<int:pid>/tasks')
@jwt_required
def get_tasks(pid):
    project = q('SELECT * FROM projects WHERE id=?', [pid], one=True)
    if not project:
        return jsonify({'error': 'Not found'}), 404
    _check_access(project, g.current_user_id)
    tasks = q('SELECT * FROM tasks WHERE project_id=? ORDER BY created_at DESC', [pid])
    return jsonify([task_to_dict(t) for t in tasks])

@app.route('/api/projects/<int:pid>/tasks', methods=['POST'])
@jwt_required
def create_task(pid):
    project = q('SELECT * FROM projects WHERE id=?', [pid], one=True)
    if not project:
        return jsonify({'error': 'Not found'}), 404
    _check_access(project, g.current_user_id)
    data = request.get_json() or {}
    if not data.get('title'):
        return jsonify({'error': 'Title required'}), 400
    due = None
    if data.get('due_date'):
        try:
            due = datetime.fromisoformat(data['due_date'].replace('Z', '+00:00')).isoformat()
        except Exception:
            return jsonify({'error': 'Invalid date'}), 400
    tid = q('''
        INSERT INTO tasks(title, description, status, priority, progress,
                          project_id, assignee_id, creator_id, due_date, gitlab_url)
        VALUES(?,?,?,?,?,?,?,?,?,?)
    ''', [data['title'], data.get('description', ''), data.get('status', 'todo'),
          data.get('priority', 'medium'), 0, pid, data.get('assignee_id'),
          g.current_user_id, due, data.get('gitlab_url', '')], commit=True)
    new_task = q('SELECT * FROM tasks WHERE id=?', [tid], one=True)
    return jsonify(task_to_dict(new_task)), 201

@app.route('/api/tasks/<int:tid>', methods=['PUT'])
@jwt_required
def update_task(tid):
    task = q('SELECT * FROM tasks WHERE id=?', [tid], one=True)
    if not task:
        return jsonify({'error': 'Not found'}), 404
    project = q('SELECT * FROM projects WHERE id=?', [task['project_id']], one=True)
    _check_access(project, g.current_user_id)
    data = request.get_json() or {}
    due = task['due_date']
    if 'due_date' in data:
        due = datetime.fromisoformat(data['due_date'].replace('Z', '+00:00')).isoformat() if data['due_date'] else None
    now = datetime.now(timezone.utc).isoformat()
    user = q('SELECT role FROM users WHERE id=?', [g.current_user_id], one=True)
    new_priority = data.get('priority', task['priority'])
    if user['role'] != 'admin' and g.current_user_id != project['owner_id'] and g.current_user_id != task['creator_id']:
        new_priority = task['priority']
    q('''
        UPDATE tasks SET title=?, description=?, status=?, priority=?,
                         assignee_id=?, due_date=?, gitlab_url=?, updated_at=?
        WHERE id=?
    ''', [data.get('title', task['title']), data.get('description', task['description']),
          data.get('status', task['status']), new_priority,
          data.get('assignee_id', task['assignee_id']), due,
          data.get('gitlab_url', task.get('gitlab_url', '')), now, tid], commit=True)
    updated = q('SELECT * FROM tasks WHERE id=?', [tid], one=True)
    return jsonify(task_to_dict(updated))

@app.route('/api/tasks/<int:tid>', methods=['DELETE'])
@jwt_required
def delete_task(tid):
    task = q('SELECT * FROM tasks WHERE id=?', [tid], one=True)
    if not task:
        return jsonify({'error': 'Not found'}), 404
    project = q('SELECT * FROM projects WHERE id=?', [task['project_id']], one=True)
    if g.current_user_id != project['owner_id'] and g.current_user_id != task['creator_id']:
        user = q('SELECT role FROM users WHERE id=?', [g.current_user_id], one=True)
        if user['role'] != 'admin':
            abort(403)
    q('DELETE FROM tasks WHERE id=?', [tid], commit=True)
    return jsonify({'message': 'Task deleted'}), 200

@app.route('/api/tasks/<int:tid>/progress', methods=['PATCH'])
@jwt_required
def update_task_progress(tid):
    task = q('SELECT * FROM tasks WHERE id=?', [tid], one=True)
    if not task:
        return jsonify({'error': 'Not found'}), 404
    if g.current_user_id != task['assignee_id']:
        user = q('SELECT role FROM users WHERE id=?', [g.current_user_id], one=True)
        if user['role'] != 'admin':
            return jsonify({'error': 'Only assignee or admin can update progress'}), 403
    data = request.get_json() or {}
    new_progress = data.get('progress')
    if new_progress is None or not isinstance(new_progress, int) or new_progress < 0 or new_progress > 100:
        return jsonify({'error': 'Progress must be integer 0-100'}), 400
    q('UPDATE tasks SET progress=?, updated_at=? WHERE id=?',
      [new_progress, datetime.now(timezone.utc).isoformat(), tid], commit=True)
    if new_progress == 100 and task['status'] != 'done':
        q('UPDATE tasks SET status="done" WHERE id=?', [tid], commit=True)
    return jsonify({'message': 'Progress updated', 'progress': new_progress})

@app.route('/api/tasks/<int:tid>/updates', methods=['GET', 'POST'])
@jwt_required
def task_updates(tid):
    task = q('SELECT * FROM tasks WHERE id=?', [tid], one=True)
    if not task:
        return jsonify({'error': 'Not found'}), 404
    project = q('SELECT * FROM projects WHERE id=?', [task['project_id']], one=True)
    _check_access(project, g.current_user_id)
    if request.method == 'GET':
        updates = q('''
            SELECT u.*, us.name as user_name, us.avatar_initials
            FROM task_updates u
            JOIN users us ON us.id = u.user_id
            WHERE u.task_id = ?
            ORDER BY u.created_at ASC
        ''', [tid])
        return jsonify(updates)
    else:
        data = request.get_json() or {}
        message = data.get('message', '').strip()
        if not message:
            return jsonify({'error': 'Message cannot be empty'}), 400
        q('INSERT INTO task_updates(task_id, user_id, message) VALUES(?,?,?)',
          [tid, g.current_user_id, message], commit=True)
        return jsonify({'message': 'Update added'}), 201

# ---------------------------- Dashboard ----------------------------
@app.route('/api/dashboard')
@jwt_required
def dashboard():
    uid = g.current_user_id
    ids = user_project_ids(uid)
    if not ids:
        return jsonify({'total_projects': 0, 'total_tasks': 0, 'my_tasks': 0,
                        'overdue_tasks': 0, 'completed_tasks': 0, 'status_breakdown': {},
                        'recent_tasks': [], 'my_recent_tasks': []})
    ph = ','.join('?' * len(ids))
    all_tasks = q(f'SELECT * FROM tasks WHERE project_id IN ({ph})', ids)
    now = datetime.now(timezone.utc)
    def is_overdue(t):
        if not t.get('due_date') or t['status'] == 'done':
            return False
        try:
            due = datetime.fromisoformat(t['due_date'].replace('Z', '+00:00'))
            if due.tzinfo is None:
                due = due.replace(tzinfo=timezone.utc)
            return due < now
        except Exception:
            return False
    status_counts = {'todo': 0, 'in_progress': 0, 'review': 0, 'done': 0}
    for t in all_tasks:
        status_counts[t['status']] = status_counts.get(t['status'], 0) + 1
    my_tasks = [t for t in all_tasks if t['assignee_id'] == uid]
    recent = sorted(all_tasks, key=lambda t: t['updated_at'], reverse=True)[:5]
    my_recent = sorted(my_tasks, key=lambda t: t['updated_at'], reverse=True)[:5]
    return jsonify({
        'total_projects': len(ids),
        'total_tasks': len(all_tasks),
        'my_tasks': len(my_tasks),
        'overdue_tasks': sum(1 for t in all_tasks if is_overdue(t)),
        'completed_tasks': status_counts.get('done', 0),
        'status_breakdown': status_counts,
        'recent_tasks': [task_to_dict(t) for t in recent],
        'my_recent_tasks': [task_to_dict(t) for t in my_recent]
    })

# ---------------------------- Admin Routes ----------------------------
@app.route('/api/admin/users')
@jwt_required
@admin_required
def admin_users():
    users = q('SELECT id, name, email, role, avatar_initials, created_at FROM users ORDER BY name')
    return jsonify(users)

@app.route('/api/admin/users', methods=['POST'])
@jwt_required
@admin_required
def admin_create_user():
    data = request.get_json() or {}
    if not all(k in data for k in ['name', 'email', 'password']):
        return jsonify({'error': 'Name, email, password required'}), 400
    email = data['email'].strip().lower()
    if q('SELECT id FROM users WHERE email=?', [email], one=True):
        return jsonify({'error': 'Email already exists'}), 409
    initials = ''.join(w[0].upper() for w in data['name'].split()[:2])
    uid = q('INSERT INTO users(name, email, password_hash, role, avatar_initials) VALUES(?,?,?,?,?)',
            [data['name'], email, hash_pw(data['password']), data.get('role', 'member'), initials],
            commit=True)
    user = q('SELECT id, name, email, role, avatar_initials, created_at FROM users WHERE id=?', [uid], one=True)
    return jsonify(user), 201

@app.route('/api/admin/projects')
@jwt_required
@admin_required
def admin_projects():
    projects = q('SELECT * FROM projects ORDER BY created_at DESC')
    return jsonify([enrich_project(p) for p in projects])

@app.route('/api/admin/tasks')
@jwt_required
@admin_required
def admin_tasks():
    tasks = q('''
        SELECT t.*, p.name as project_name, u.name as assignee_name
        FROM tasks t
        LEFT JOIN projects p ON t.project_id = p.id
        LEFT JOIN users u ON t.assignee_id = u.id
        ORDER BY t.created_at DESC
    ''')
    return jsonify([task_to_dict(t) for t in tasks])

@app.route('/api/admin/stats')
@jwt_required
@admin_required
def admin_stats():
    total_users = q('SELECT COUNT(*) as c FROM users', one=True)['c']
    total_projects = q('SELECT COUNT(*) as c FROM projects', one=True)['c']
    total_tasks = q('SELECT COUNT(*) as c FROM tasks', one=True)['c']
    completed_tasks = q('SELECT COUNT(*) as c FROM tasks WHERE status="done"', one=True)['c']
    user_stats = q('''
        SELECT u.id, u.name, u.email,
               COUNT(t.id) as total_assigned,
               SUM(CASE WHEN t.status = 'done' THEN 1 ELSE 0 END) as completed,
               SUM(CASE WHEN t.status != 'done' AND t.due_date < datetime('now') THEN 1 ELSE 0 END) as overdue,
               AVG(t.progress) as avg_progress
        FROM users u
        LEFT JOIN tasks t ON u.id = t.assignee_id
        GROUP BY u.id
        ORDER BY u.name
    ''')
    for s in user_stats:
        s['avg_progress'] = round(s['avg_progress'] or 0)
        s['completed'] = s['completed'] or 0
        s['overdue'] = s['overdue'] or 0
    return jsonify({
        'total_users': total_users,
        'total_projects': total_projects,
        'total_tasks': total_tasks,
        'completed_tasks': completed_tasks,
        'user_stats': user_stats
    })

@app.route('/api/admin/employee_projects/<int:uid>')
@jwt_required
@admin_required
def admin_employee_projects(uid):
    projects = q('''
        SELECT DISTINCT p.*
        FROM projects p
        LEFT JOIN project_members pm ON p.id = pm.project_id
        WHERE p.owner_id = ? OR pm.user_id = ?
    ''', [uid, uid])
    result = []
    for p in projects:
        user_tasks = q('SELECT COUNT(*) as c FROM tasks WHERE project_id=? AND assignee_id=?', [p['id'], uid], one=True)['c']
        user_done = q('SELECT COUNT(*) as c FROM tasks WHERE project_id=? AND assignee_id=? AND status="done"', [p['id'], uid], one=True)['c']
        user_progress = round(user_done / user_tasks * 100) if user_tasks else 0
        result.append({**p, 'user_tasks': user_tasks, 'user_done': user_done, 'user_progress': user_progress})
    return jsonify(result)

# ---------- TASK DISTRIBUTION (with GitLab URL) ----------
@app.route('/api/admin/distribute-task', methods=['POST'])
@jwt_required
@admin_required
def distribute_task():
    data = request.get_json() or {}
    required = ['project_id', 'title', 'employee_ids']
    if not all(k in data for k in required):
        return jsonify({'error': 'project_id, title and employee_ids are required'}), 400

    project_id = data['project_id']
    title = data['title'].strip()
    if not title:
        return jsonify({'error': 'Task title cannot be empty'}), 400

    description = data.get('description', '').strip()
    priority = data.get('priority', 'medium')
    gitlab_url = data.get('gitlab_url', '').strip()
    due_date = None
    if data.get('due_date'):
        try:
            due_date = datetime.fromisoformat(data['due_date'].replace('Z', '+00:00')).isoformat()
        except Exception:
            return jsonify({'error': 'Invalid due_date format'}), 400

    employee_ids = list(set(data['employee_ids']))
    if not employee_ids:
        return jsonify({'error': 'At least one employee must be selected'}), 400

    # Verify project exists
    project = q('SELECT * FROM projects WHERE id=?', [project_id], one=True)
    if not project:
        return jsonify({'error': 'Project not found'}), 404

    # Verify all employee_ids exist
    placeholders = ','.join('?' * len(employee_ids))
    existing = q(f'SELECT id FROM users WHERE id IN ({placeholders})', employee_ids)
    existing_ids = {u['id'] for u in existing}
    invalid = [eid for eid in employee_ids if eid not in existing_ids]
    if invalid:
        return jsonify({'error': f'Invalid employee IDs: {invalid}'}), 400

    created_tasks = []
    now_iso = datetime.now(timezone.utc).isoformat()
    for emp_id in employee_ids:
        tid = q('''
            INSERT INTO tasks(title, description, status, priority, progress,
                              project_id, assignee_id, creator_id, due_date, gitlab_url,
                              created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ''', [title, description, 'todo', priority, 0,
              project_id, emp_id, g.current_user_id, due_date, gitlab_url,
              now_iso, now_iso],
        commit=True)
        created_tasks.append(tid)

    return jsonify({
        'message': f'{len(created_tasks)} task(s) created successfully',
        'task_ids': created_tasks
    }), 201

# ---------------------------- Messaging Routes ----------------------------
@app.route('/api/messages')
@jwt_required
def get_messages():
    messages = q('''
        SELECT m.*, u.name as from_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.to_user_id = ?
        ORDER BY m.created_at DESC
    ''', [g.current_user_id])
    return jsonify(messages)

@app.route('/api/admin/messages', methods=['POST'])
@jwt_required
@admin_required
def send_message():
    data = request.get_json() or {}
    if not all(k in data for k in ['to_user_id', 'message']):
        return jsonify({'error': 'to_user_id and message required'}), 400
    to_user = q('SELECT id FROM users WHERE id=?', [data['to_user_id']], one=True)
    if not to_user:
        return jsonify({'error': 'Recipient not found'}), 404
    q('INSERT INTO messages(from_user_id, to_user_id, message) VALUES(?,?,?)',
      [g.current_user_id, data['to_user_id'], data['message']], commit=True)
    return jsonify({'message': 'Message sent'}), 201

# ---------------------------- JSON Error Handlers ----------------------------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    index_path = os.path.join(BASE_DIR, 'index.html')
    if not os.path.exists(index_path):
        return "index.html not found", 500
    with open(index_path, 'r', encoding='utf-8') as f:
        return f.read(), 200, {'Content-Type': 'text/html'}

@app.errorhandler(405)
def method_not_allowed(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Method not allowed'}), 405
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(403)
def forbidden(e):
    return jsonify({'error': 'Forbidden – admin access required'}), 403

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ---------------------------- Static Frontend ----------------------------
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    # Never serve HTML for API paths – return JSON 404 instead
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    index_path = os.path.join(BASE_DIR, 'index.html')
    if not os.path.exists(index_path):
        return "index.html not found", 500
    with open(index_path, 'r', encoding='utf-8') as f:
        return f.read(), 200, {'Content-Type': 'text/html'}

# ---------------------------- Database Seeding ----------------------------
def seed():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0:
        db.close()
        return
    now = datetime.now(timezone.utc)
    users_data = [
        ('Admin User', 'admin@teamhub.com', 'admin', 'admin123'),
        ('Alice Chen', 'alice@teamhub.com', 'member', 'alice123'),
        ('Bob Smith', 'bob@teamhub.com', 'member', 'bob123')
    ]
    user_ids = {}
    for name, email, role, pw in users_data:
        initials = ''.join(w[0].upper() for w in name.split()[:2])
        cursor = db.execute('INSERT INTO users(name, email, password_hash, role, avatar_initials) VALUES(?,?,?,?,?)',
                            [name, email, hash_pw(pw), role, initials])
        user_ids[email] = cursor.lastrowid
    db.commit()
    admin_id = user_ids['admin@teamhub.com']
    alice_id = user_ids['alice@teamhub.com']
    bob_id = user_ids['bob@teamhub.com']
    p1 = db.execute('INSERT INTO projects(name, description, owner_id) VALUES(?,?,?)',
                    ['Website Redesign', 'Revamp the company site with new branding', admin_id]).lastrowid
    p2 = db.execute('INSERT INTO projects(name, description, owner_id) VALUES(?,?,?)',
                    ['Mobile App v2', 'New features for mobile', alice_id]).lastrowid
    db.execute('INSERT INTO project_members(project_id, user_id) VALUES(?,?)', [p1, alice_id])
    db.execute('INSERT INTO project_members(project_id, user_id) VALUES(?,?)', [p1, bob_id])
    db.execute('INSERT INTO project_members(project_id, user_id) VALUES(?,?)', [p2, admin_id])
    db.execute('INSERT INTO project_members(project_id, user_id) VALUES(?,?)', [p2, bob_id])
    tasks_seed = [
        ('Design new homepage', 'Figma mockups for all pages', 'done', 'high', p1, alice_id, admin_id, (now - timedelta(days=5)).isoformat(), 100, ''),
        ('Setup CI/CD pipeline', 'GitHub Actions + Docker', 'in_progress', 'urgent', p1, bob_id, admin_id, (now + timedelta(days=2)).isoformat(), 40, ''),
        ('Write API docs', 'Swagger + Postman', 'todo', 'medium', p1, bob_id, alice_id, (now - timedelta(days=1)).isoformat(), 0, ''),
        ('Push notifications', 'Firebase FCM integration', 'review', 'high', p2, admin_id, alice_id, (now + timedelta(days=7)).isoformat(), 80, ''),
        ('User onboarding', 'Interactive walkthrough', 'todo', 'medium', p2, alice_id, alice_id, (now + timedelta(days=14)).isoformat(), 0, ''),
        ('Fix login bug', 'JWT refresh token issue', 'in_progress', 'urgent', p1, bob_id, bob_id, (now + timedelta(days=1)).isoformat(), 20, ''),
    ]
    for t in tasks_seed:
        db.execute('''
            INSERT INTO tasks(title, description, status, priority, project_id,
                              assignee_id, creator_id, due_date, progress, gitlab_url)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        ''', t)
    db.commit()
    db.close()

# ---------------------------- Main Entrypoint ----------------------------
if __name__ == '__main__':
    init_db()
    seed()
    app.run(debug=False, host='0.0.0.0', port=5000)