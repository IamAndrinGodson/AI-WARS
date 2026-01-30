"""
Data Ingestion Module for ML Threat Detection System
Handles collection from multiple sources: NetFlow, sFlow, SIEM, packet capture
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

import pandas as pd
from kafka import KafkaProducer
from elasticsearch import Elasticsearch
import redis

logger = logging.getLogger(__name__)


class DataCollector(ABC):
    """Abstract base class for data collectors"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.is_running = False
        
    @abstractmethod
    async def collect(self) -> pd.DataFrame:
        """Collect data from source"""
        pass
    
    @abstractmethod
    async def start(self):
        """Start the collector"""
        pass
    
    @abstractmethod
    async def stop(self):
        """Stop the collector"""
        pass


class NetFlowCollector(DataCollector):
    """NetFlow v5/v9/IPFIX collector"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 2055)
        self.buffer_size = config.get('buffer_size', 65535)
        self.server = None
        
    async def collect(self) -> pd.DataFrame:
        """Collect NetFlow records"""
        records = []
        
        try:
            # Simplified NetFlow parsing (in production, use proper NetFlow library)
            data, addr = await self.server.recvfrom(self.buffer_size)
            
            # Parse NetFlow packets
            flow_record = self._parse_netflow(data)
            if flow_record:
                records.append(flow_record)
                
        except Exception as e:
            logger.error(f"Error collecting NetFlow data: {e}")
        
        return pd.DataFrame(records)
    
    def _parse_netflow(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse NetFlow packet (simplified)"""
        try:
            # In production, implement full NetFlow v5/v9/IPFIX parsing
            return {
                'timestamp': datetime.now().isoformat(),
                'src_ip': '0.0.0.0',
                'dst_ip': '0.0.0.0',
                'src_port': 0,
                'dst_port': 0,
                'protocol': 0,
                'packets': 0,
                'bytes': 0,
                'flow_duration': 0,
            }
        except Exception as e:
            logger.error(f"Error parsing NetFlow: {e}")
            return None
    
    async def start(self):
        """Start NetFlow collector"""
        logger.info(f"Starting NetFlow collector on {self.host}:{self.port}")
        # In production, implement proper UDP server
        self.is_running = True
        
    async def stop(self):
        """Stop NetFlow collector"""
        logger.info("Stopping NetFlow collector")
        self.is_running = False


class SIEMIntegration(DataCollector):
    """SIEM Integration (Splunk, Elasticsearch, QRadar)"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.siem_type = config.get('type', 'splunk')
        self.host = config.get('host')
        self.port = config.get('port')
        self.api_key = config.get('api_key')
        
    async def collect(self) -> pd.DataFrame:
        """Collect data from SIEM"""
        if self.siem_type == 'elasticsearch':
            return await self._collect_from_elasticsearch()
        elif self.siem_type == 'splunk':
            return await self._collect_from_splunk()
        else:
            logger.warning(f"Unsupported SIEM type: {self.siem_type}")
            return pd.DataFrame()
    
    async def _collect_from_elasticsearch(self) -> pd.DataFrame:
        """Collect from Elasticsearch"""
        try:
            es = Elasticsearch([f"{self.host}:{self.port}"])
            
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-5m",
                            "lte": "now"
                        }
                    }
                },
                "size": 10000
            }
            
            result = es.search(index="security-*", body=query)
            hits = result['hits']['hits']
            
            records = [hit['_source'] for hit in hits]
            return pd.DataFrame(records)
            
        except Exception as e:
            logger.error(f"Error collecting from Elasticsearch: {e}")
            return pd.DataFrame()
    
    async def _collect_from_splunk(self) -> pd.DataFrame:
        """Collect from Splunk (simplified)"""
        # In production, use Splunk SDK
        logger.info("Collecting from Splunk")
        return pd.DataFrame()
    
    async def start(self):
        """Start SIEM integration"""
        logger.info(f"Starting SIEM integration: {self.siem_type}")
        self.is_running = True
        
    async def stop(self):
        """Stop SIEM integration"""
        logger.info("Stopping SIEM integration")
        self.is_running = False


class DataIngestionPipeline:
    """Main data ingestion pipeline orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.collectors: List[DataCollector] = []
        self.kafka_producer = None
        self.redis_client = None
        
        self._initialize_collectors()
        self._initialize_streaming()
        
    def _initialize_collectors(self):
        """Initialize all enabled collectors"""
        collector_config = self.config.get('data_pipeline', {}).get('collectors', {})
        
        if collector_config.get('netflow', {}).get('enabled'):
            self.collectors.append(
                NetFlowCollector(collector_config['netflow'])
            )
        
        if collector_config.get('siem_integration', {}).get('enabled'):
            self.collectors.append(
                SIEMIntegration(collector_config['siem_integration'])
            )
    
    def _initialize_streaming(self):
        """Initialize streaming infrastructure"""
        try:
            # Initialize Kafka producer for streaming
            self.kafka_producer = KafkaProducer(
                bootstrap_servers=['localhost:9092'],
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            
            # Initialize Redis for caching
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                decode_responses=True
            )
            
            logger.info("Streaming infrastructure initialized")
        except Exception as e:
            logger.warning(f"Could not initialize streaming: {e}")
    
    async def start_all_collectors(self):
        """Start all collectors concurrently"""
        logger.info(f"Starting {len(self.collectors)} collectors")
        
        tasks = [collector.start() for collector in self.collectors]
        await asyncio.gather(*tasks)
        
        # Start collection loop
        await self.collection_loop()
    
    async def collection_loop(self):
        """Main collection loop"""
        logger.info("Starting data collection loop")
        
        while True:
            try:
                # Collect from all sources
                collection_tasks = [
                    collector.collect() for collector in self.collectors
                ]
                results = await asyncio.gather(*collection_tasks)
                
                # Combine and process data
                combined_df = pd.concat(results, ignore_index=True)
                
                if not combined_df.empty:
                    await self._process_batch(combined_df)
                
                # Wait before next collection
                await asyncio.sleep(60)  # Collect every minute
                
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                await asyncio.sleep(5)
    
    async def _process_batch(self, df: pd.DataFrame):
        """Process and route collected data"""
        logger.info(f"Processing batch of {len(df)} records")
        
        try:
            # Store raw data
            self._store_raw_data(df)
            
            # Stream to Kafka for real-time processing
            if self.kafka_producer:
                for record in df.to_dict('records'):
                    self.kafka_producer.send('raw-security-events', record)
            
            # Cache recent data in Redis
            if self.redis_client:
                cache_key = f"recent_events:{datetime.now().strftime('%Y%m%d%H%M')}"
                self.redis_client.setex(
                    cache_key,
                    3600,  # 1 hour TTL
                    df.to_json()
                )
                
        except Exception as e:
            logger.error(f"Error processing batch: {e}")
    
    def _store_raw_data(self, df: pd.DataFrame):
        """Store raw data to data lake"""
        storage_config = self.config.get('data_pipeline', {}).get('storage', {})
        raw_path = storage_config.get('raw_data', {}).get('path', 'data/raw')
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{raw_path}/events_{timestamp}.parquet"
        
        df.to_parquet(filename, compression='snappy')
        logger.info(f"Stored raw data to {filename}")
    
    async def stop_all_collectors(self):
        """Stop all collectors"""
        logger.info("Stopping all collectors")
        
        tasks = [collector.stop() for collector in self.collectors]
        await asyncio.gather(*tasks)
        
        if self.kafka_producer:
            self.kafka_producer.close()


async def main():
    """Main entry point for data ingestion"""
    import yaml
    
    # Load configuration
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Create and start pipeline
    pipeline = DataIngestionPipeline(config)
    
    try:
        await pipeline.start_all_collectors()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        await pipeline.stop_all_collectors()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    asyncio.run(main())
