"""Typed configuration for the Neo4j infrastructure adapter."""

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class Neo4jSettings(BaseModel):
    """Connection settings supplied by the composition root, never global state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    uri: str = Field(pattern=r"^neo4j(\+s|\+ssc)?://.+|^bolt(\+s|\+ssc)?://.+")
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr
    database: str = Field(default="neo4j", min_length=1, max_length=128)
    encrypted: bool = True
    max_connection_pool_size: int = Field(default=50, ge=1, le=500)
