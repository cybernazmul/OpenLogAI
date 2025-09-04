#!/usr/bin/env python3
"""
OpenSearch MCP Tools - Client and utilities for OpenSearch operations
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import OpenSearchException

logger = logging.getLogger(__name__)


class OpenSearchClient:
    """OpenSearch client wrapper for MCP server operations"""
    
    def __init__(
        self,
        url: str = "https://localhost:9200",
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_certs: bool = False,
        ssl_assert_hostname: bool = False,
        ssl_show_warn: bool = False,
        timeout: int = 30,
        max_retries: int = 3
    ):
        """
        Initialize OpenSearch client
        
        Args:
            url: OpenSearch URL
            username: Authentication username
            password: Authentication password
            api_key: API key for authentication (alternative to username/password)
            verify_certs: Whether to verify SSL certificates
            ssl_assert_hostname: Whether to assert SSL hostname
            ssl_show_warn: Whether to show SSL warnings
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries
        """
        self.url = url
        self.username = username
        self.password = password
        self.api_key = api_key
        
        # Parse URL to extract components
        parsed_url = urlparse(url)
        self.host = parsed_url.hostname or "localhost"
        self.port = parsed_url.port or (443 if parsed_url.scheme == "https" else 9200)
        self.use_ssl = parsed_url.scheme == "https"
        
        # Initialize client
        self.client = None
        self._initialize_client(
            verify_certs=verify_certs,
            ssl_assert_hostname=ssl_assert_hostname,
            ssl_show_warn=ssl_show_warn,
            timeout=timeout,
            max_retries=max_retries
        )
    
    def _initialize_client(
        self,
        verify_certs: bool,
        ssl_assert_hostname: bool,
        ssl_show_warn: bool,
        timeout: int,
        max_retries: int
    ):
        """Initialize the OpenSearch client with proper configuration"""
        try:
            # Prepare authentication
            auth = None
            headers = {}
            
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"
            elif self.username and self.password:
                auth = (self.username, self.password)
            
            # Configure client parameters
            client_config = {
                "hosts": [{"host": self.host, "port": self.port}],
                "http_auth": auth,
                "use_ssl": self.use_ssl,
                "verify_certs": verify_certs,
                "ssl_assert_hostname": ssl_assert_hostname,
                "ssl_show_warn": ssl_show_warn,
                "connection_class": RequestsHttpConnection,
                "timeout": timeout,
                "max_retries": max_retries,
                "retry_on_timeout": True,
                "headers": headers if headers else None
            }
            
            # Remove None values
            client_config = {k: v for k, v in client_config.items() if v is not None}
            
            self.client = OpenSearch(**client_config)
            logger.info(f"OpenSearch client initialized for {self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenSearch client: {e}")
            self.client = None
            raise
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check OpenSearch cluster health
        
        Returns:
            Dictionary with health status and connection info
        """
        if not self.client:
            return {
                "connected": False,
                "error": "Client not initialized"
            }
        
        try:
            # Basic ping test
            if not self.client.ping():
                return {
                    "connected": False,
                    "error": "Ping failed - OpenSearch not reachable"
                }
            
            # Get cluster health
            health = self.client.cluster.health()
            
            # Get basic cluster info
            info = self.client.info()
            
            return {
                "connected": True,
                "cluster_name": health.get("cluster_name"),
                "cluster_status": health.get("status"),
                "number_of_nodes": health.get("number_of_nodes"),
                "number_of_data_nodes": health.get("number_of_data_nodes"),
                "active_primary_shards": health.get("active_primary_shards"),
                "active_shards": health.get("active_shards"),
                "relocating_shards": health.get("relocating_shards"),
                "initializing_shards": health.get("initializing_shards"),
                "unassigned_shards": health.get("unassigned_shards"),
                "version": info.get("version", {}).get("number"),
                "distribution": info.get("version", {}).get("distribution"),
                "url": self.url
            }
            
        except OpenSearchException as e:
            logger.error(f"OpenSearch health check failed: {e}")
            return {
                "connected": False,
                "error": f"OpenSearch error: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "connected": False,
                "error": f"Connection error: {str(e)}"
            }
    
    def list_indices(
        self,
        pattern: str = "*",
        include_system: bool = False
    ) -> List[Dict[str, Any]]:
        """
        List indices with metadata
        
        Args:
            pattern: Index pattern to match
            include_system: Whether to include system indices (starting with .)
            
        Returns:
            List of index information dictionaries
        """
        if not self.client:
            raise ValueError("Client not initialized")
        
        try:
            indices = self.client.cat.indices(
                index=pattern,
                format='json',
                bytes='b',
                h='index,status,health,docs.count,store.size,pri,rep'
            )
            
            if not include_system:
                indices = [idx for idx in indices if not idx.get('index', '').startswith('.')]
            
            result = []
            for idx in indices:
                result.append({
                    "index": idx.get('index'),
                    "status": idx.get('status'),
                    "health": idx.get('health'),
                    "doc_count": int(idx.get('docs.count', 0)) if idx.get('docs.count') else 0,
                    "store_size_bytes": int(idx.get('store.size', 0)) if idx.get('store.size') else 0,
                    "primary_shards": int(idx.get('pri', 0)) if idx.get('pri') else 0,
                    "replica_shards": int(idx.get('rep', 0)) if idx.get('rep') else 0
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to list indices: {e}")
            raise
    
    def get_mapping(self, index: str) -> Dict[str, Any]:
        """
        Get mapping for an index
        
        Args:
            index: Index name or pattern
            
        Returns:
            Mapping information
        """
        if not self.client:
            raise ValueError("Client not initialized")
        
        try:
            return self.client.indices.get_mapping(index=index)
        except Exception as e:
            logger.error(f"Failed to get mapping for {index}: {e}")
            raise
    
    def search(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 10,
        from_offset: int = 0,
        fields: Optional[List[str]] = None,
        sort: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Search documents in OpenSearch
        
        Args:
            index: Index name or pattern
            query: OpenSearch query DSL
            size: Number of results to return
            from_offset: Starting offset for pagination
            fields: Fields to include in results
            sort: Sort configuration
            
        Returns:
            Search results
        """
        if not self.client:
            raise ValueError("Client not initialized")
        
        try:
            search_body = {
                "query": query,
                "size": min(size, 10000),  # OpenSearch default limit
                "from": from_offset
            }
            
            if fields:
                search_body["_source"] = fields
                
            if sort:
                search_body["sort"] = sort
            
            response = self.client.search(index=index, body=search_body)
            
            return {
                "took": response.get("took", 0),
                "total_hits": response["hits"]["total"]["value"],
                "max_score": response["hits"].get("max_score"),
                "hits": response["hits"]["hits"]
            }
            
        except Exception as e:
            logger.error(f"Search failed for index {index}: {e}")
            raise
    
    def execute_sql(self, query: str, format_type: str = "json") -> Dict[str, Any]:
        """
        Execute SQL query using OpenSearch SQL plugin
        
        Args:
            query: SQL query string
            format_type: Response format (json, csv, raw)
            
        Returns:
            Query results
        """
        if not self.client:
            raise ValueError("Client not initialized")
        
        try:
            response = self.client.transport.perform_request(
                'POST',
                '/_plugins/_sql',
                body={
                    'query': query,
                    'format': format_type
                }
            )
            
            return {
                "query": query,
                "format": format_type,
                "results": response
            }
            
        except Exception as e:
            logger.error(f"SQL execution failed: {e}")
            raise
    
    def close(self):
        """Close the client connection"""
        if self.client:
            try:
                # OpenSearch client doesn't have an explicit close method
                # but we can clear the reference
                self.client = None
                logger.info("OpenSearch client connection closed")
            except Exception as e:
                logger.error(f"Error closing client: {e}")