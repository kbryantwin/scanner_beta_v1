import os
from psycopg2.pool import SimpleConnectionPool

# Initialize connection pool on import
MIN_CONN = int(os.environ.get('DB_POOL_MIN', 1))
MAX_CONN = int(os.environ.get('DB_POOL_MAX', 10))
DATABASE_URL = os.environ.get('DATABASE_URL')

if not DATABASE_URL:
    raise RuntimeError('DATABASE_URL environment variable not set')

_pool = SimpleConnectionPool(MIN_CONN, MAX_CONN, dsn=DATABASE_URL)


def get_conn():
    """Get a connection from the pool"""
    return _pool.getconn()


def put_conn(conn):
    """Return a connection to the pool"""
    if conn:
        _pool.putconn(conn)


def close_all():
    """Close all connections in the pool"""
    _pool.closeall()
