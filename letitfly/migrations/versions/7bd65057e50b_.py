"""empty message

Revision ID: 7bd65057e50b
Revises: 793b9bc21c7a
Create Date: 2017-10-21 10:22:13.013765

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7bd65057e50b'
down_revision = '793b9bc21c7a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('drives',
    sa.Column('ride_id', sa.Integer(), nullable=False),
    sa.Column('start_location', sa.String(length=50), nullable=True),
    sa.Column('end_location', sa.String(length=50), nullable=True),
    sa.Column('time_finished', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('ride_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('drives')
    # ### end Alembic commands ###
