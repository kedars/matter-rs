use crate::{data_model::objects::ClusterType, error::*, interaction_model::core::IMStatusCode};

use std::fmt;

pub const CLUSTERS_PER_ENDPT: usize = 7;

pub struct Endpoint {
    clusters: Vec<Box<dyn ClusterType>>,
}

impl Endpoint {
    pub fn new() -> Result<Box<Endpoint>, Error> {
        Ok(Box::new(Endpoint {
            clusters: Vec::with_capacity(CLUSTERS_PER_ENDPT),
        }))
    }

    pub fn add_cluster(&mut self, cluster: Box<dyn ClusterType>) -> Result<(), Error> {
        if self.clusters.len() < self.clusters.capacity() {
            self.clusters.push(cluster);
            Ok(())
        } else {
            Err(Error::NoSpace)
        }
    }

    fn get_cluster_index(&self, cluster_id: u32) -> Option<usize> {
        self.clusters.iter().position(|c| c.base().id == cluster_id)
    }

    pub fn get_cluster(&self, cluster_id: u32) -> Result<&dyn ClusterType, Error> {
        let index = self
            .get_cluster_index(cluster_id)
            .ok_or(Error::ClusterNotFound)?;
        Ok(self.clusters[index].as_ref())
    }

    pub fn get_cluster_mut(&mut self, cluster_id: u32) -> Result<&mut dyn ClusterType, Error> {
        let index = self
            .get_cluster_index(cluster_id)
            .ok_or(Error::ClusterNotFound)?;
        Ok(self.clusters[index].as_mut())
    }

    // Returns a slice of clusters, with either a single cluster or all (wildcard)
    pub fn get_wildcard_clusters(
        &self,
        cluster: Option<u32>,
    ) -> Result<(&[Box<dyn ClusterType>], bool), IMStatusCode> {
        if let Some(c) = cluster {
            if let Some(i) = self.get_cluster_index(c) {
                Ok((&self.clusters[i..i + 1], false))
            } else {
                Err(IMStatusCode::UnsupportedCluster)
            }
        } else {
            Ok((self.clusters.as_slice(), true))
        }
    }

    // Returns a slice of clusters, with either a single cluster or all (wildcard)
    pub fn get_wildcard_clusters_mut(
        &mut self,
        cluster: Option<u32>,
    ) -> Result<(&mut [Box<dyn ClusterType>], bool), IMStatusCode> {
        if let Some(c) = cluster {
            if let Some(i) = self.get_cluster_index(c) {
                Ok((&mut self.clusters[i..i + 1], false))
            } else {
                Err(IMStatusCode::UnsupportedCluster)
            }
        } else {
            Ok((&mut self.clusters[..], true))
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "clusters:[")?;
        let mut comma = "";
        for element in self.clusters.iter() {
            write!(f, "{} {{ {} }}", comma, element.base())?;
            comma = ", ";
        }
        write!(f, "]")
    }
}
